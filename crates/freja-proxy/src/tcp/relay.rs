use std::time::Duration;

use bytes::{Bytes, BytesMut};
use freja_domain::Direction;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, sleep_until},
};

use crate::{ProxyError, ShutdownSignal, inspection::FlowInspector};

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayLimits {
    idle_timeout: Duration,
    preflight_bytes: usize,
    preflight_timeout: Duration,
}

impl RelayLimits {
    pub(crate) const fn new(
        idle_timeout: Duration,
        preflight_bytes: usize,
        preflight_timeout: Duration,
    ) -> Self {
        Self {
            idle_timeout,
            preflight_bytes,
            preflight_timeout,
        }
    }

    pub(crate) const fn inspection_bytes(self) -> usize {
        self.preflight_bytes
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RelayStats {
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayTermination {
    Completed,
    IdleTimeout,
    Shutdown,
    InspectionBlocked,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayResult {
    pub stats: RelayStats,
    pub termination: RelayTermination,
}

#[derive(Clone, Copy)]
enum ControlledWrite {
    Written,
    IdleTimeout,
    Shutdown,
}

enum PreflightBuffer {
    Pending {
        bytes: BytesMut,
        deadline: Option<Instant>,
    },
    Released,
}

impl PreflightBuffer {
    fn new(enabled: bool, maximum: usize) -> Self {
        if enabled {
            Self::Pending {
                bytes: BytesMut::with_capacity(maximum),
                deadline: None,
            }
        } else {
            Self::Released
        }
    }

    fn read_size(&self, buffer_size: usize, maximum: usize) -> usize {
        match self {
            Self::Pending { bytes, .. } => maximum.saturating_sub(bytes.len()).min(buffer_size),
            Self::Released => buffer_size,
        }
    }

    fn push(&mut self, input: &[u8], maximum: usize, budget: Duration) -> Option<Bytes> {
        let Self::Pending { bytes, deadline } = self else {
            return Some(Bytes::copy_from_slice(input));
        };
        if deadline.is_none() {
            *deadline = Some(Instant::now() + budget);
        }
        bytes.extend_from_slice(input);
        if bytes.len() < maximum {
            return None;
        }
        Some(self.release())
    }

    fn release(&mut self) -> Bytes {
        match std::mem::replace(self, Self::Released) {
            Self::Pending { bytes, .. } => bytes.freeze(),
            Self::Released => Bytes::new(),
        }
    }

    const fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Pending { deadline, .. } => *deadline,
            Self::Released => None,
        }
    }

    const fn has_deadline(&self) -> bool {
        self.deadline().is_some()
    }
}

enum ForwardResult {
    Forwarded(u64),
    Dropped,
    Blocked,
    Stopped(RelayTermination),
}

// Keeping both directional branches in one select loop makes the shared idle,
// shutdown, half-close, and preflight transitions explicit and atomic.
#[allow(clippy::too_many_lines)]
pub(crate) async fn relay<Client, Upstream>(
    mut client: Client,
    mut upstream: Upstream,
    limits: RelayLimits,
    mut shutdown: ShutdownSignal,
    mut inspection: Option<FlowInspector>,
) -> Result<RelayResult, ProxyError>
where
    Client: AsyncRead + AsyncWrite + Unpin,
    Upstream: AsyncRead + AsyncWrite + Unpin,
{
    let mut stats = RelayStats::default();
    let mut client_open = true;
    let mut upstream_open = true;
    let mut client_buffer = vec![0_u8; 16 * 1_024].into_boxed_slice();
    let mut upstream_buffer = vec![0_u8; 16 * 1_024].into_boxed_slice();
    let preflight = inspection
        .as_ref()
        .is_some_and(FlowInspector::uses_preflight);
    let mut client_preflight = PreflightBuffer::new(preflight, limits.preflight_bytes);
    let mut upstream_preflight = PreflightBuffer::new(preflight, limits.preflight_bytes);
    let mut deadline = Instant::now() + limits.idle_timeout;

    loop {
        if !client_open && !upstream_open {
            return Ok(terminated(stats, RelayTermination::Completed));
        }
        let client_read_size =
            client_preflight.read_size(client_buffer.len(), limits.preflight_bytes);
        let upstream_read_size =
            upstream_preflight.read_size(upstream_buffer.len(), limits.preflight_bytes);
        tokio::select! {
            () = shutdown.cancelled() => {
                return Ok(terminated(stats, RelayTermination::Shutdown));
            }
            () = sleep_until(deadline) => {
                return Ok(terminated(stats, RelayTermination::IdleTimeout));
            }
            () = wait_for_preflight(client_preflight.deadline()), if client_preflight.has_deadline() => {
                let bytes = client_preflight.release();
                let outcome = forward_chunk(
                    inspection.as_mut(),
                    Direction::ClientToUpstream,
                    &bytes,
                    limits.preflight_bytes,
                    &mut upstream,
                    deadline,
                    &mut shutdown,
                    "client-to-upstream",
                ).await?;
                match outcome {
                    ForwardResult::Forwarded(count) => {
                        stats.client_to_upstream_bytes = stats.client_to_upstream_bytes.saturating_add(count);
                    }
                    ForwardResult::Dropped => {}
                    ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                    ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                }
            }
            () = wait_for_preflight(upstream_preflight.deadline()), if upstream_preflight.has_deadline() => {
                let bytes = upstream_preflight.release();
                let outcome = forward_chunk(
                    inspection.as_mut(),
                    Direction::UpstreamToClient,
                    &bytes,
                    limits.preflight_bytes,
                    &mut client,
                    deadline,
                    &mut shutdown,
                    "upstream-to-client",
                ).await?;
                match outcome {
                    ForwardResult::Forwarded(count) => {
                        stats.upstream_to_client_bytes = stats.upstream_to_client_bytes.saturating_add(count);
                    }
                    ForwardResult::Dropped => {}
                    ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                    ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                }
            }
            read = client.read(&mut client_buffer[..client_read_size]), if client_open => {
                let count = read.map_err(|source| ProxyError::RelayRead {
                    direction: "client-to-upstream",
                    source,
                })?;
                if count == 0 {
                    let bytes = client_preflight.release();
                    if !bytes.is_empty() {
                        let outcome = forward_chunk(
                            inspection.as_mut(),
                            Direction::ClientToUpstream,
                            &bytes,
                            limits.preflight_bytes,
                            &mut upstream,
                            deadline,
                            &mut shutdown,
                            "client-to-upstream",
                        ).await?;
                        match outcome {
                            ForwardResult::Forwarded(count) => {
                                stats.client_to_upstream_bytes = stats.client_to_upstream_bytes.saturating_add(count);
                            }
                            ForwardResult::Dropped => {}
                            ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                            ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                        }
                    }
                    client_open = false;
                    upstream.shutdown().await.map_err(|source| ProxyError::RelayWrite {
                        direction: "client-to-upstream-shutdown",
                        source,
                    })?;
                } else {
                    deadline = Instant::now() + limits.idle_timeout;
                    let Some(bytes) = client_preflight.push(
                        &client_buffer[..count],
                        limits.preflight_bytes,
                        limits.preflight_timeout,
                    ) else {
                        continue;
                    };
                    let outcome = forward_chunk(
                        inspection.as_mut(),
                        Direction::ClientToUpstream,
                        &bytes,
                        limits.preflight_bytes,
                        &mut upstream,
                        deadline,
                        &mut shutdown,
                        "client-to-upstream",
                    ).await?;
                    match outcome {
                        ForwardResult::Forwarded(count) => {
                            stats.client_to_upstream_bytes = stats.client_to_upstream_bytes.saturating_add(count);
                        }
                        ForwardResult::Dropped => {}
                        ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                        ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                    }
                }
            }
            read = upstream.read(&mut upstream_buffer[..upstream_read_size]), if upstream_open => {
                let count = read.map_err(|source| ProxyError::RelayRead {
                    direction: "upstream-to-client",
                    source,
                })?;
                if count == 0 {
                    let bytes = upstream_preflight.release();
                    if !bytes.is_empty() {
                        let outcome = forward_chunk(
                            inspection.as_mut(),
                            Direction::UpstreamToClient,
                            &bytes,
                            limits.preflight_bytes,
                            &mut client,
                            deadline,
                            &mut shutdown,
                            "upstream-to-client",
                        ).await?;
                        match outcome {
                            ForwardResult::Forwarded(count) => {
                                stats.upstream_to_client_bytes = stats.upstream_to_client_bytes.saturating_add(count);
                            }
                            ForwardResult::Dropped => {}
                            ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                            ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                        }
                    }
                    upstream_open = false;
                    client.shutdown().await.map_err(|source| ProxyError::RelayWrite {
                        direction: "upstream-to-client-shutdown",
                        source,
                    })?;
                } else {
                    deadline = Instant::now() + limits.idle_timeout;
                    let Some(bytes) = upstream_preflight.push(
                        &upstream_buffer[..count],
                        limits.preflight_bytes,
                        limits.preflight_timeout,
                    ) else {
                        continue;
                    };
                    let outcome = forward_chunk(
                        inspection.as_mut(),
                        Direction::UpstreamToClient,
                        &bytes,
                        limits.preflight_bytes,
                        &mut client,
                        deadline,
                        &mut shutdown,
                        "upstream-to-client",
                    ).await?;
                    match outcome {
                        ForwardResult::Forwarded(count) => {
                            stats.upstream_to_client_bytes = stats.upstream_to_client_bytes.saturating_add(count);
                        }
                        ForwardResult::Dropped => {}
                        ForwardResult::Blocked => return Ok(inspection_blocked(stats)),
                        ForwardResult::Stopped(termination) => return Ok(terminated(stats, termination)),
                    }
                }
            }
        }
    }
}

async fn wait_for_preflight(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

// Direction, transform budget, idle deadline, shutdown, and audit/error label
// are independent controls at this single write commitment boundary.
#[allow(clippy::too_many_arguments)]
async fn forward_chunk<Stream>(
    inspection: Option<&mut FlowInspector>,
    direction: Direction,
    bytes: &[u8],
    maximum_replacement_bytes: usize,
    stream: &mut Stream,
    deadline: Instant,
    shutdown: &mut ShutdownSignal,
    direction_name: &'static str,
) -> Result<ForwardResult, ProxyError>
where
    Stream: AsyncWrite + Unpin,
{
    let bytes = match process_chunk(inspection, direction, bytes, maximum_replacement_bytes).await?
    {
        ChunkProcess::Blocked => return Ok(ForwardResult::Blocked),
        ChunkProcess::Dropped => return Ok(ForwardResult::Dropped),
        ChunkProcess::Forward(bytes) => bytes,
    };
    match write_with_controls(stream, &bytes, deadline, shutdown, direction_name).await? {
        ControlledWrite::Written => Ok(ForwardResult::Forwarded(count_as_u64(bytes.len()))),
        ControlledWrite::IdleTimeout => Ok(ForwardResult::Stopped(RelayTermination::IdleTimeout)),
        ControlledWrite::Shutdown => Ok(ForwardResult::Stopped(RelayTermination::Shutdown)),
    }
}

const fn inspection_blocked(stats: RelayStats) -> RelayResult {
    terminated(stats, RelayTermination::InspectionBlocked)
}

const fn terminated(stats: RelayStats, termination: RelayTermination) -> RelayResult {
    RelayResult { stats, termination }
}

enum ChunkProcess {
    Blocked,
    Dropped,
    Forward(bytes::Bytes),
}

async fn process_chunk(
    inspection: Option<&mut FlowInspector>,
    direction: Direction,
    bytes: &[u8],
    maximum_replacement_bytes: usize,
) -> Result<ChunkProcess, ProxyError> {
    let Some(inspection) = inspection else {
        return Ok(ChunkProcess::Forward(bytes::Bytes::copy_from_slice(bytes)));
    };
    if !inspection.permits(direction, bytes).await? {
        return Ok(ChunkProcess::Blocked);
    }
    match inspection
        .transform_tcp_chunk(direction, bytes, maximum_replacement_bytes)
        .await?
    {
        Some(bytes) => Ok(ChunkProcess::Forward(bytes)),
        None => Ok(ChunkProcess::Dropped),
    }
}

async fn write_with_controls<Stream>(
    stream: &mut Stream,
    bytes: &[u8],
    deadline: Instant,
    shutdown: &mut ShutdownSignal,
    direction: &'static str,
) -> Result<ControlledWrite, ProxyError>
where
    Stream: AsyncWrite + Unpin,
{
    tokio::select! {
        () = shutdown.cancelled() => Ok(ControlledWrite::Shutdown),
        () = sleep_until(deadline) => Ok(ControlledWrite::IdleTimeout),
        result = stream.write_all(bytes) => {
            result.map_err(|source| ProxyError::RelayWrite {
                direction,
                source,
            })?;
            Ok(ControlledWrite::Written)
        },
    }
}

fn count_as_u64(count: usize) -> u64 {
    let Ok(count) = u64::try_from(count) else {
        return u64::MAX;
    };
    count
}
