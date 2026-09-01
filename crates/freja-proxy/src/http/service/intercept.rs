use super::connect::tunnel_error_outcome;
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{SessionId, TransactionId};
use http::{Request, Response, Version};
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use super::{
    DataPlaneServices, ForwardTarget, HttpService, ProxyBody, ProxyError, RelayStats,
    ShutdownSignal, audit_context,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InterceptedProtocol {
    Http1,
    Http2,
}

impl InterceptedProtocol {
    pub(super) const fn http_version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
        }
    }
}

pub(super) enum InterceptedUpstreamSender {
    Http1(http1::SendRequest<ProxyBody>),
    Http2(http2::SendRequest<ProxyBody>),
}

impl InterceptedUpstreamSender {
    pub(super) async fn send_request(
        &mut self,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, ProxyError> {
        match self {
            Self::Http1(sender) => {
                sender
                    .ready()
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/1 readiness",
                        source,
                    })?;
                sender
                    .send_request(request)
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/1 request",
                        source,
                    })
            }
            Self::Http2(sender) => {
                sender
                    .ready()
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/2 readiness",
                        source,
                    })?;
                sender
                    .send_request(request)
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/2 request",
                        source,
                    })
            }
        }
    }
}
#[derive(Clone, Default)]
struct PlaintextCounters {
    client_to_upstream: Arc<AtomicU64>,
    upstream_to_client: Arc<AtomicU64>,
}

impl PlaintextCounters {
    fn stats(&self) -> RelayStats {
        RelayStats {
            client_to_upstream_bytes: self.client_to_upstream.load(Ordering::Relaxed),
            upstream_to_client_bytes: self.upstream_to_client.load(Ordering::Relaxed),
        }
    }
}

struct ReadCountingIo<T> {
    inner: T,
    bytes: Arc<AtomicU64>,
}

impl<T> ReadCountingIo<T> {
    fn new(inner: T, bytes: Arc<AtomicU64>) -> Self {
        Self { inner, bytes }
    }

    fn record(&self, count: usize) {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        let _update = self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(count))
            });
    }
}

impl<T> AsyncRead for ReadCountingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let previous = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.record(buffer.filled().len().saturating_sub(previous));
        }
        result
    }
}

impl<T> AsyncWrite for ReadCountingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_intercepted_tunnel(
    on_upgrade: OnUpgrade,
    upstream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    interceptor: std::sync::Arc<crate::TlsInterceptor>,
    target: ForwardTarget,
    selected_address: SocketAddr,
    service: HttpService,
    services: DataPlaneServices,
    session_id: SessionId,
    transaction_id: TransactionId,
    connect_timeout: std::time::Duration,
    idle_timeout: std::time::Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError> {
    let counters = PlaintextCounters::default();
    let active_counters = counters.clone();
    let result = Box::pin(async {
        let upgraded = tokio::select! {
            () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
            result = on_upgrade => result.map_err(ProxyError::HttpUpgrade)?,
        };
        let downstream = tokio::select! {
            () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
            result = timeout(idle_timeout, acceptor.accept(TokioIo::new(upgraded))) => {
                match result {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(source)) => {
                        return Err(ProxyError::Tls(crate::TlsError::DownstreamHandshake(source)));
                    }
                    Err(_) => {
                        return Err(ProxyError::Tls(
                            crate::TlsError::DownstreamHandshakeTimedOut,
                        ));
                    }
                }
            }
        };
        let downstream_alpn = downstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let upstream = match timeout(
            connect_timeout,
            interceptor.connect_upstream(upstream, target.host(), downstream_alpn.as_deref()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(ProxyError::Tls(error)),
            Err(_) => return Err(ProxyError::UpstreamResponseTimedOut),
        };
        validate_intercepted_alpn(
            downstream_alpn.as_deref(),
            upstream.get_ref().1.alpn_protocol(),
        )?;
        let protocol = match downstream_alpn.as_deref() {
            Some(b"h2") => InterceptedProtocol::Http2,
            Some(b"http/1.1") | None => InterceptedProtocol::Http1,
            Some(protocol) => {
                return Err(ProxyError::Tls(
                    crate::TlsError::UnsupportedApplicationProtocol {
                        protocol: String::from_utf8_lossy(protocol).into_owned(),
                    },
                ));
            }
        };
        services
            .publish(AuditEnvelope {
                context: audit_context(session_id, Some(transaction_id), &services),
                event: AuditEvent::TlsInterceptionEstablished {
                    hostname: target.host().to_string(),
                    alpn: downstream_alpn
                        .as_deref()
                        .map(|value| String::from_utf8_lossy(value).into_owned()),
                },
            })
            .await?;
        let downstream =
            ReadCountingIo::new(downstream, Arc::clone(&active_counters.client_to_upstream));
        let upstream =
            ReadCountingIo::new(upstream, Arc::clone(&active_counters.upstream_to_client));
        serve_intercepted_http(
            protocol,
            downstream,
            upstream,
            service,
            target,
            selected_address,
            idle_timeout,
            shutdown,
        )
        .await
    })
    .await;
    let stats = counters.stats();
    let outcome = match &result {
        Ok(()) => "completed",
        Err(error) => intercepted_tunnel_error_outcome(error),
    };
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, Some(transaction_id), &services),
            event: AuditEvent::TunnelClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome: outcome.to_owned(),
            },
        })
        .await?;
    result
}

const fn intercepted_tunnel_error_outcome(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::Tls(crate::TlsError::DownstreamHandshake(_)) => "tls-client-rejected",
        ProxyError::Tls(crate::TlsError::DownstreamHandshakeTimedOut) => "tls-client-timeout",
        ProxyError::Tls(crate::TlsError::UpstreamHandshake { .. }) => "tls-upstream-rejected",
        ProxyError::Tls(
            crate::TlsError::ApplicationProtocolMismatch { .. }
            | crate::TlsError::UnsupportedApplicationProtocol { .. },
        ) => "tls-alpn-rejected",
        ProxyError::UpstreamResponseTimedOut => "tls-upstream-timeout",
        other => tunnel_error_outcome(other),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_intercepted_http<Downstream, Upstream>(
    protocol: InterceptedProtocol,
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    idle_timeout: std::time::Duration,
    shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match protocol {
        InterceptedProtocol::Http1 => {
            serve_intercepted_http1(
                downstream,
                upstream,
                service,
                target,
                selected_address,
                shutdown,
            )
            .await
        }
        InterceptedProtocol::Http2 => {
            serve_intercepted_http2(
                downstream,
                upstream,
                service,
                target,
                selected_address,
                idle_timeout,
                shutdown,
            )
            .await
        }
    }
}

async fn serve_intercepted_http1<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = service.limits;
    let (sender, upstream_connection) = http1::handshake::<_, ProxyBody>(TokioIo::new(upstream))
        .await
        .map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/1 handshake",
            source,
        })?;
    let sender = Arc::new(Mutex::new(InterceptedUpstreamSender::Http1(sender)));
    let request_service = service_fn(move |request| {
        let service = service.clone();
        let target = target.clone();
        let sender = Arc::clone(&sender);
        async move {
            service
                .handle_intercepted(
                    request,
                    &target,
                    selected_address,
                    InterceptedProtocol::Http1,
                    &sender,
                )
                .await
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.read_timeout)
        .max_buf_size(limits.header_bytes.max(8 * 1_024));
    let downstream_connection = builder.serve_connection(TokioIo::new(downstream), request_service);
    tokio::pin!(downstream_connection);
    tokio::pin!(upstream_connection);
    tokio::select! {
        () = shutdown.cancelled() => Err(ProxyError::Shutdown),
        result = &mut downstream_connection => result.map_err(ProxyError::HttpConnection),
        result = &mut upstream_connection => result.map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/1 connection",
            source,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_intercepted_http2<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    idle_timeout: std::time::Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = service.limits;
    let maximum_headers = u32::try_from(limits.header_bytes).unwrap_or(u32::MAX);
    let maximum_streams = u32::try_from(limits.connections).unwrap_or(u32::MAX);
    let mut client_builder = http2::Builder::new(TokioExecutor::new());
    client_builder
        .max_header_list_size(maximum_headers)
        .max_concurrent_streams(maximum_streams);
    let (sender, upstream_connection) = client_builder
        .handshake::<_, ProxyBody>(TokioIo::new(upstream))
        .await
        .map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/2 handshake",
            source,
        })?;
    let sender = Arc::new(Mutex::new(InterceptedUpstreamSender::Http2(sender)));
    let request_service = service_fn(move |request| {
        let service = service.clone();
        let target = target.clone();
        let sender = Arc::clone(&sender);
        async move {
            service
                .handle_intercepted(
                    request,
                    &target,
                    selected_address,
                    InterceptedProtocol::Http2,
                    &sender,
                )
                .await
        }
    });
    let mut server_builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    server_builder
        .timer(TokioTimer::new())
        .max_header_list_size(maximum_headers)
        .max_concurrent_streams(maximum_streams)
        .keep_alive_interval(idle_timeout)
        .keep_alive_timeout(idle_timeout);
    let downstream_connection =
        server_builder.serve_connection(TokioIo::new(downstream), request_service);
    tokio::pin!(downstream_connection);
    tokio::pin!(upstream_connection);
    tokio::select! {
        () = shutdown.cancelled() => Err(ProxyError::Shutdown),
        result = &mut downstream_connection => result.map_err(ProxyError::HttpConnection),
        result = &mut upstream_connection => result.map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/2 connection",
            source,
        }),
    }
}

fn validate_intercepted_alpn(
    downstream: Option<&[u8]>,
    upstream: Option<&[u8]>,
) -> Result<(), ProxyError> {
    let compatible = matches!(
        (downstream, upstream),
        (Some(b"h2"), Some(b"h2")) | (Some(b"http/1.1") | None, Some(b"http/1.1") | None)
    );
    if compatible {
        return Ok(());
    }
    Err(ProxyError::Tls(
        crate::TlsError::ApplicationProtocolMismatch {
            downstream: downstream.map(|value| String::from_utf8_lossy(value).into_owned()),
            upstream: upstream.map(|value| String::from_utf8_lossy(value).into_owned()),
        },
    ))
}
