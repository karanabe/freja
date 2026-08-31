use std::{error::Error, fmt, net::SocketAddr, sync::Arc, time::Duration};

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_config::Limits;
use freja_domain::{
    Port, Protocol, ProxyCredentialHash, RequestedTargetFacts, SessionId, Socks5Listener,
    TargetHost,
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::warn;

use crate::{
    DataPlaneServices, ProxyError, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any},
    inspection::FlowInspector,
    tcp::relay::{RelayLimits, RelayStats, RelayTermination, relay},
};

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const AUTH_NONE: u8 = 0;
const AUTH_USERNAME_PASSWORD: u8 = 2;
const AUTH_UNACCEPTABLE: u8 = 0xff;

/// Bound SOCKS5 CONNECT listener introduced after the initial static-L4 MVP.
pub struct Socks5Server {
    listener: TcpListener,
    local_address: SocketAddr,
    specification: Socks5Listener,
    services: DataPlaneServices,
    limits: Limits,
}

impl Socks5Server {
    /// Binds a validated SOCKS5 listener.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if the socket cannot be bound or queried.
    pub async fn bind(
        specification: Socks5Listener,
        services: DataPlaneServices,
        limits: Limits,
    ) -> Result<Self, ProxyError> {
        let bind = specification.bind().address();
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| ProxyError::Bind { bind, source })?;
        let local_address = listener.local_addr().map_err(ProxyError::LocalAddress)?;
        Ok(Self {
            listener,
            local_address,
            specification,
            services,
            limits,
        })
    }

    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Accepts bounded SOCKS5 sessions until graceful shutdown.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] for listener, audit, or task-join failures.
    pub async fn run(self, mut shutdown: ShutdownSignal) -> Result<(), ProxyError> {
        let concurrency = Arc::new(Semaphore::new(self.limits.connections));
        let mut sessions = JoinSet::new();
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                joined = sessions.join_next(), if !sessions.is_empty() => handle_join(joined)?,
                accepted = self.listener.accept() => {
                    let (client, peer) = accepted.map_err(ProxyError::Accept)?;
                    let permit = match Arc::clone(&concurrency).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(tokio::sync::TryAcquireError::NoPermits) => {
                            audit_capacity_rejection(peer, self.local_address, &self.services).await?;
                            drop(client);
                            continue;
                        }
                        Err(tokio::sync::TryAcquireError::Closed) => {
                            return Err(ProxyError::ConcurrencyClosed);
                        }
                    };
                    let context = SessionContext {
                        peer,
                        listener: self.local_address,
                        authentication: self.specification.authentication(),
                        services: self.services.clone(),
                        limits: self.limits,
                        shutdown: shutdown.clone(),
                    };
                    sessions.spawn(async move {
                        let _permit = permit;
                        serve_session(client, context).await
                    });
                }
            }
        }
        while let Some(joined) = sessions.join_next().await {
            handle_join(Some(joined))?;
        }
        Ok(())
    }
}

struct SessionContext {
    peer: SocketAddr,
    listener: SocketAddr,
    authentication: Option<ProxyCredentialHash>,
    services: DataPlaneServices,
    limits: Limits,
    shutdown: ShutdownSignal,
}

async fn serve_session(mut client: TcpStream, context: SessionContext) -> Result<(), ProxyError> {
    let session_id = SessionId::new();
    context
        .services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &context.services),
            event: AuditEvent::ConnectionAccepted {
                client: context.peer.to_string(),
                listener: context.listener.to_string(),
            },
        })
        .await?;
    context.services.publish_flow_opened(
        session_id,
        context.peer.to_string(),
        "socks5-handshake".to_owned(),
    );
    let result = run_socks_session(&mut client, session_id, &context).await;
    let (stats, outcome) = match &result {
        Ok(relay) => (relay.stats, relay_outcome(relay.termination)),
        Err(error) => (RelayStats::default(), error_outcome(error)),
    };
    context
        .services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &context.services),
            event: AuditEvent::FlowClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome: outcome.to_owned(),
            },
        })
        .await?;
    context.services.publish_flow_closed(
        session_id,
        stats.client_to_upstream_bytes,
        stats.upstream_to_client_bytes,
    );
    result.map(|_| ())
}

async fn run_socks_session(
    client: &mut TcpStream,
    session_id: SessionId,
    context: &SessionContext,
) -> Result<crate::tcp::relay::RelayResult, ProxyError> {
    negotiate_authentication(
        client,
        context.authentication,
        context.limits.connect_timeout,
        session_id,
        &context.services,
    )
    .await?;
    let (host, port) = read_request(client, context.limits.connect_timeout).await?;
    context.services.publish_flow_opened(
        session_id,
        context.peer.to_string(),
        format!("{host}:{port}"),
    );
    let requested = RequestedTargetFacts::new(context.peer.ip(), host, port, Protocol::Tcp);
    let mut shutdown = context.shutdown.clone();
    let addresses = match authorize_and_resolve(
        &requested,
        &context.services,
        session_id,
        None,
        context.limits.connect_timeout,
        &mut shutdown,
    )
    .await
    {
        Ok(addresses) => addresses,
        Err(error) => {
            send_reply(client, 2, None, context.limits.connect_timeout).await?;
            return Err(error);
        }
    };
    let (upstream, _) =
        match connect_any(&addresses, context.limits.connect_timeout, &mut shutdown).await {
            Ok(connected) => connected,
            Err(error) => {
                send_reply(
                    client,
                    reply_for_proxy_error(&error),
                    None,
                    context.limits.connect_timeout,
                )
                .await?;
                return Err(error);
            }
        };
    let bound = upstream.local_addr().ok();
    send_reply(client, 0, bound, context.limits.connect_timeout).await?;
    let inspection = FlowInspector::new(
        context.services.clone(),
        session_id,
        None,
        Protocol::Tcp,
        context.limits.body_prefix_bytes,
    );
    relay(
        client,
        upstream,
        RelayLimits::new(
            context.limits.idle_timeout,
            context.limits.body_prefix_bytes,
            context.limits.read_timeout,
        ),
        shutdown,
        Some(inspection),
    )
    .await
}

async fn negotiate_authentication(
    client: &mut TcpStream,
    authentication: Option<ProxyCredentialHash>,
    budget: Duration,
    session_id: SessionId,
    services: &DataPlaneServices,
) -> Result<(), ProxyError> {
    let mut greeting = [0_u8; 2];
    read_exact(client, &mut greeting, budget, "greeting").await?;
    if greeting[0] != SOCKS_VERSION {
        return Err(ProxyError::Socks(SocksError::UnsupportedVersion));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    read_exact(client, &mut methods, budget, "authentication methods").await?;
    let desired = if authentication.is_some() {
        AUTH_USERNAME_PASSWORD
    } else {
        AUTH_NONE
    };
    if !methods.contains(&desired) {
        write_all(
            client,
            &[SOCKS_VERSION, AUTH_UNACCEPTABLE],
            budget,
            "method rejection",
        )
        .await?;
        return Err(ProxyError::Socks(SocksError::NoAcceptableAuthentication));
    }
    write_all(
        client,
        &[SOCKS_VERSION, desired],
        budget,
        "method selection",
    )
    .await?;
    let Some(expected) = authentication else {
        return Ok(());
    };
    let authenticated = authenticate_username_password(client, expected, budget).await?;
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, services),
            event: AuditEvent::ProxyAuthentication {
                outcome: if authenticated {
                    "accepted"
                } else {
                    "rejected"
                }
                .to_owned(),
            },
        })
        .await?;
    write_all(
        client,
        &[AUTH_VERSION, u8::from(!authenticated)],
        budget,
        "authentication response",
    )
    .await?;
    if !authenticated {
        return Err(ProxyError::Socks(SocksError::AuthenticationFailed));
    }
    Ok(())
}

async fn authenticate_username_password(
    client: &mut TcpStream,
    expected: ProxyCredentialHash,
    budget: Duration,
) -> Result<bool, ProxyError> {
    let mut header = [0_u8; 2];
    read_exact(client, &mut header, budget, "authentication username").await?;
    if header[0] != AUTH_VERSION || header[1] == 0 {
        return Ok(false);
    }
    let mut credential = vec![0_u8; usize::from(header[1])];
    read_exact(client, &mut credential, budget, "authentication username").await?;
    let mut password_length = [0_u8; 1];
    read_exact(
        client,
        &mut password_length,
        budget,
        "authentication password length",
    )
    .await?;
    if password_length[0] == 0 {
        credential.fill(0);
        return Ok(false);
    }
    credential.push(b':');
    let username_and_separator = credential.len();
    credential.resize(
        username_and_separator.saturating_add(usize::from(password_length[0])),
        0,
    );
    read_exact(
        client,
        &mut credential[username_and_separator..],
        budget,
        "authentication password",
    )
    .await?;
    let candidate = Sha256::digest(&credential);
    credential.fill(0);
    Ok(constant_time_equal(&candidate, expected.as_bytes()))
}

async fn read_request(
    client: &mut TcpStream,
    budget: Duration,
) -> Result<(TargetHost, Port), ProxyError> {
    let mut header = [0_u8; 4];
    read_exact(client, &mut header, budget, "request header").await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(ProxyError::Socks(SocksError::MalformedRequest));
    }
    if header[1] != 1 {
        send_reply(client, 7, None, budget).await?;
        return Err(ProxyError::Socks(SocksError::UnsupportedCommand));
    }
    let host = match header[3] {
        1 => {
            let mut octets = [0_u8; 4];
            read_exact(client, &mut octets, budget, "IPv4 address").await?;
            TargetHost::Ip(octets.into())
        }
        3 => {
            let mut length = [0_u8; 1];
            read_exact(client, &mut length, budget, "domain length").await?;
            if length[0] == 0 {
                return Err(ProxyError::Socks(SocksError::MalformedRequest));
            }
            let mut name = vec![0_u8; usize::from(length[0])];
            read_exact(client, &mut name, budget, "domain").await?;
            let name = String::from_utf8(name)
                .map_err(SocksError::InvalidDomainEncoding)
                .map_err(ProxyError::Socks)?;
            TargetHost::parse(name)
                .map_err(SocksError::InvalidTarget)
                .map_err(ProxyError::Socks)?
        }
        4 => {
            let mut octets = [0_u8; 16];
            read_exact(client, &mut octets, budget, "IPv6 address").await?;
            TargetHost::Ip(octets.into())
        }
        _ => {
            send_reply(client, 8, None, budget).await?;
            return Err(ProxyError::Socks(SocksError::UnsupportedAddressType));
        }
    };
    let mut port = [0_u8; 2];
    read_exact(client, &mut port, budget, "destination port").await?;
    let port = Port::new(u16::from_be_bytes(port))
        .map_err(SocksError::InvalidTarget)
        .map_err(ProxyError::Socks)?;
    Ok((host, port))
}

async fn send_reply(
    client: &mut TcpStream,
    status: u8,
    bound: Option<SocketAddr>,
    budget: Duration,
) -> Result<(), ProxyError> {
    let bound = bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut response = vec![SOCKS_VERSION, status, 0];
    match bound {
        SocketAddr::V4(address) => {
            response.push(1);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            response.push(4);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    write_all(client, &response, budget, "CONNECT reply").await
}

async fn read_exact(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    budget: Duration,
    stage: &'static str,
) -> Result<(), ProxyError> {
    match timeout(budget, stream.read_exact(bytes)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(source)) => Err(ProxyError::Socks(SocksError::Io { stage, source })),
        Err(_) => Err(ProxyError::Socks(SocksError::TimedOut { stage })),
    }
}

async fn write_all(
    stream: &mut TcpStream,
    bytes: &[u8],
    budget: Duration,
    stage: &'static str,
) -> Result<(), ProxyError> {
    match timeout(budget, stream.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(source)) => Err(ProxyError::Socks(SocksError::Io { stage, source })),
        Err(_) => Err(ProxyError::Socks(SocksError::TimedOut { stage })),
    }
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

const fn reply_for_proxy_error(error: &ProxyError) -> u8 {
    match error {
        ProxyError::ConnectTimedOut { .. } => 6,
        ProxyError::ConnectFailed { .. } => 5,
        ProxyError::Dns { .. }
        | ProxyError::DnsTimedOut { .. }
        | ProxyError::NoResolvedAddresses { .. } => 4,
        _ => 1,
    }
}

async fn audit_capacity_rejection(
    peer: SocketAddr,
    listener: SocketAddr,
    services: &DataPlaneServices,
) -> Result<(), ProxyError> {
    let session_id = SessionId::new();
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, services),
            event: AuditEvent::ConnectionAccepted {
                client: peer.to_string(),
                listener: listener.to_string(),
            },
        })
        .await?;
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, services),
            event: AuditEvent::FlowClosed {
                client_to_upstream_bytes: 0,
                upstream_to_client_bytes: 0,
                outcome: "connection-limit".to_owned(),
            },
        })
        .await
}

fn handle_join(
    joined: Option<Result<Result<(), ProxyError>, tokio::task::JoinError>>,
) -> Result<(), ProxyError> {
    match joined {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => {
            warn!(error = %error, "SOCKS5 session ended with an error");
            Ok(())
        }
        Some(Err(error)) => Err(ProxyError::Join(error)),
    }
}

const fn relay_outcome(termination: RelayTermination) -> &'static str {
    match termination {
        RelayTermination::Completed => "completed",
        RelayTermination::IdleTimeout => "idle-timeout",
        RelayTermination::Shutdown => "shutdown",
        RelayTermination::InspectionBlocked => "inspection-blocked",
    }
}

const fn error_outcome(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::PolicyDenied { .. } => "policy-denied",
        ProxyError::DetourLoop { .. } => "detour-loop",
        ProxyError::Socks(SocksError::AuthenticationFailed) => "authentication-failed",
        ProxyError::Socks(_) => "socks-protocol-error",
        ProxyError::ConnectTimedOut { .. } => "connect-timeout",
        ProxyError::ConnectFailed { .. } => "connect-failure",
        ProxyError::Dns { .. } | ProxyError::NoResolvedAddresses { .. } => "dns-failure",
        ProxyError::DnsTimedOut { .. } => "dns-timeout",
        ProxyError::Shutdown => "shutdown",
        _ => "runtime-failure",
    }
}

/// SOCKS5 negotiation or authentication failure.
#[derive(Debug)]
pub enum SocksError {
    Io {
        stage: &'static str,
        source: std::io::Error,
    },
    TimedOut {
        stage: &'static str,
    },
    UnsupportedVersion,
    NoAcceptableAuthentication,
    AuthenticationFailed,
    UnsupportedCommand,
    UnsupportedAddressType,
    MalformedRequest,
    InvalidDomainEncoding(std::string::FromUtf8Error),
    InvalidTarget(freja_domain::EndpointError),
}

impl fmt::Display for SocksError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { stage, .. } => write!(formatter, "SOCKS5 {stage} I/O failed"),
            Self::TimedOut { stage } => write!(formatter, "SOCKS5 {stage} timed out"),
            Self::UnsupportedVersion => formatter.write_str("unsupported SOCKS version"),
            Self::NoAcceptableAuthentication => {
                formatter.write_str("client offered no acceptable SOCKS5 authentication method")
            }
            Self::AuthenticationFailed => formatter.write_str("SOCKS5 authentication failed"),
            Self::UnsupportedCommand => formatter.write_str("unsupported SOCKS5 command"),
            Self::UnsupportedAddressType => formatter.write_str("unsupported SOCKS5 address type"),
            Self::MalformedRequest => formatter.write_str("malformed SOCKS5 request"),
            Self::InvalidDomainEncoding(_) => {
                formatter.write_str("SOCKS5 domain is not valid UTF-8")
            }
            Self::InvalidTarget(_) => formatter.write_str("SOCKS5 target is invalid"),
        }
    }
}

impl Error for SocksError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidDomainEncoding(source) => Some(source),
            Self::InvalidTarget(source) => Some(source),
            Self::TimedOut { .. }
            | Self::UnsupportedVersion
            | Self::NoAcceptableAuthentication
            | Self::AuthenticationFailed
            | Self::UnsupportedCommand
            | Self::UnsupportedAddressType
            | Self::MalformedRequest => None,
        }
    }
}
