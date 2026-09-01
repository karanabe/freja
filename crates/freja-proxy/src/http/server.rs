use std::{net::SocketAddr, sync::Arc, time::Duration};

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{HttpForwardListener, RuleId, SessionId};
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tracing::warn;

use super::{
    service::{ConnectionTaskHandle, HttpService},
    wire::RequestCaptureIo,
};
use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal, destination::audit_context,
};

const MINIMUM_HTTP1_READ_BUFFER_BYTES: usize = 8 * 1_024;

/// Bound pure-Tokio HTTP/1 explicit forward-proxy listener.
pub struct HttpForwardServer {
    listener: TcpListener,
    local_address: SocketAddr,
    specification: HttpForwardListener,
    connect_port_rule: RuleId,
    services: DataPlaneServices,
    limits: ProxyLimits,
}

impl HttpForwardServer {
    /// Binds a validated HTTP forward listener without starting its accept loop.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] when binding, querying the bound address, or
    /// constructing the built-in CONNECT port decision rule fails.
    pub async fn bind(
        specification: HttpForwardListener,
        services: DataPlaneServices,
        limits: ProxyLimits,
    ) -> Result<Self, ProxyError> {
        let bind = specification.bind().address();
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| ProxyError::Bind { bind, source })?;
        let local_address = listener.local_addr().map_err(ProxyError::LocalAddress)?;
        let connect_port_rule =
            RuleId::new("connect-port-allowlist").map_err(ProxyError::InternalPolicy)?;
        Ok(Self {
            listener,
            local_address,
            specification,
            connect_port_rule,
            services,
            limits,
        })
    }

    /// Returns the actual bound listener address.
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Accepts HTTP/1 connections until shutdown and drains CONNECT tunnels.
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
                joined = sessions.join_next(), if !sessions.is_empty() => {
                    handle_join(joined)?;
                }
                accepted = self.listener.accept() => {
                    let (client, peer) = accepted.map_err(ProxyError::Accept)?;
                    let permit = match Arc::clone(&concurrency).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(tokio::sync::TryAcquireError::NoPermits) => {
                            self.reject_at_capacity(peer).await?;
                            drop(client);
                            continue;
                        }
                        Err(tokio::sync::TryAcquireError::Closed) => {
                            return Err(ProxyError::ConcurrencyClosed);
                        }
                    };
                    let service_context = ConnectionContext {
                        peer,
                        listener: self.local_address,
                        specification: self.specification.clone(),
                        connect_port_rule: self.connect_port_rule.clone(),
                        services: self.services.clone(),
                        limits: self.limits,
                        shutdown: shutdown.clone(),
                    };
                    sessions.spawn(async move {
                        let _permit = permit;
                        serve_connection(client, service_context).await
                    });
                }
            }
        }
        while let Some(joined) = sessions.join_next().await {
            handle_join(Some(joined))?;
        }
        Ok(())
    }

    async fn reject_at_capacity(&self, peer: SocketAddr) -> Result<(), ProxyError> {
        let session_id = SessionId::new();
        self.services
            .publish(AuditEnvelope {
                context: audit_context(session_id, None, &self.services),
                event: AuditEvent::ConnectionAccepted {
                    client: peer.to_string(),
                    listener: self.local_address.to_string(),
                },
            })
            .await?;
        self.services
            .publish(AuditEnvelope {
                context: audit_context(session_id, None, &self.services),
                event: AuditEvent::FlowClosed {
                    client_to_upstream_bytes: 0,
                    upstream_to_client_bytes: 0,
                    outcome: "connection-limit".to_owned(),
                },
            })
            .await
    }
}

struct ConnectionContext {
    peer: SocketAddr,
    listener: SocketAddr,
    specification: HttpForwardListener,
    connect_port_rule: RuleId,
    services: DataPlaneServices,
    limits: ProxyLimits,
    shutdown: ShutdownSignal,
}

async fn serve_connection(
    client: tokio::net::TcpStream,
    context: ConnectionContext,
) -> Result<(), ProxyError> {
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
        "http-forward".to_owned(),
    );
    let (task_sender, task_receiver) = tokio::sync::mpsc::channel::<ConnectionTaskHandle>(1);
    let tracker = tokio::spawn(track_connection_tasks(task_receiver));
    let connection_result = if let Some(capture) = context.services.ui_capture_settings() {
        let (client, capture_handle) = RequestCaptureIo::new(
            client,
            context.services.clone(),
            session_id,
            context.limits.header_bytes,
            capture.content_bytes(),
            capture.retained_rows(),
        );
        let service = HttpService::new(
            context.peer,
            session_id,
            context.connect_port_rule,
            context.specification,
            context.services.clone(),
            context.limits,
            context.shutdown.clone(),
            task_sender,
            Some(capture_handle),
        );
        run_hyper_connection(
            client,
            service,
            context.limits.header_bytes,
            context.limits.read_timeout,
            context.shutdown.clone(),
        )
        .await
    } else {
        let service = HttpService::new(
            context.peer,
            session_id,
            context.connect_port_rule,
            context.specification,
            context.services.clone(),
            context.limits,
            context.shutdown.clone(),
            task_sender,
            None,
        );
        run_hyper_connection(
            client,
            service,
            context.limits.header_bytes,
            context.limits.read_timeout,
            context.shutdown.clone(),
        )
        .await
    };
    let tracked_result = tracker.await.map_err(ProxyError::Join)?;
    let outcome = if connection_result.is_err() || tracked_result.is_err() {
        "http-error"
    } else {
        "completed"
    };
    context
        .services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &context.services),
            event: AuditEvent::FlowClosed {
                client_to_upstream_bytes: 0,
                upstream_to_client_bytes: 0,
                outcome: outcome.to_owned(),
            },
        })
        .await?;
    context.services.publish_flow_closed(session_id, 0, 0);
    connection_result?;
    tracked_result
}

async fn run_hyper_connection<Stream>(
    client: Stream,
    service: HttpService,
    header_bytes: usize,
    read_timeout: Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hyper_service = service_fn(move |request| {
        let service = service.clone();
        async move { service.handle(request).await }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(read_timeout)
        .max_buf_size(header_bytes.max(MINIMUM_HTTP1_READ_BUFFER_BYTES));
    let connection = builder
        .serve_connection(TokioIo::new(client), hyper_service)
        .with_upgrades();
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result.map_err(ProxyError::HttpConnection),
        () = shutdown.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await.map_err(ProxyError::HttpConnection)
        }
    }
}

async fn track_connection_tasks(
    mut receiver: tokio::sync::mpsc::Receiver<ConnectionTaskHandle>,
) -> Result<(), ProxyError> {
    let mut receiver_open = true;
    let mut tasks = JoinSet::new();
    while receiver_open || !tasks.is_empty() {
        tokio::select! {
            handle = receiver.recv(), if receiver_open => {
                match handle {
                    Some(handle) => {
                        tasks.spawn(async move { handle.await.map_err(ProxyError::Join)? });
                    }
                    None => receiver_open = false,
                }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                let Some(joined) = joined else {
                    continue;
                };
                joined.map_err(ProxyError::Join)??;
            }
        }
    }
    Ok(())
}

fn handle_join(
    joined: Option<Result<Result<(), ProxyError>, tokio::task::JoinError>>,
) -> Result<(), ProxyError> {
    match joined {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => {
            warn!(error = %error, "HTTP forward session ended with an error");
            Ok(())
        }
        Some(Err(error)) => Err(ProxyError::Join(error)),
    }
}
