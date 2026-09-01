use super::session::{SessionContext, serve_session};
use std::{net::SocketAddr, sync::Arc};

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{SessionId, Socks5Listener};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tracing::warn;

use super::{DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal, audit_context};

/// Bound SOCKS5 CONNECT listener introduced after the initial static-L4 MVP.
pub struct Socks5Server {
    listener: TcpListener,
    local_address: SocketAddr,
    specification: Socks5Listener,
    services: DataPlaneServices,
    limits: ProxyLimits,
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
        limits: ProxyLimits,
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

    /// Returns the operating-system-selected bound address after [`Self::bind`].
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
