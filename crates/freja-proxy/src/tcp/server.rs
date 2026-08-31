use std::{net::SocketAddr, sync::Arc};

use freja_audit::{AuditContext, AuditEnvelope, AuditEvent, UnixMillis};
use freja_config::Limits;
use freja_domain::{SessionId, TcpStaticListener};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet};
use tracing::warn;

use super::session::run_static_session;
use crate::{DataPlaneServices, ProxyError, ShutdownSignal};

/// Bound pure-Tokio static TCP listener behind Freja's engine boundary.
pub struct StaticTcpServer {
    listener: TcpListener,
    local_address: SocketAddr,
    specification: TcpStaticListener,
    services: DataPlaneServices,
    limits: Limits,
}

impl StaticTcpServer {
    /// Binds a validated static TCP listener without starting its accept loop.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] when binding or querying the bound address fails.
    pub async fn bind(
        specification: TcpStaticListener,
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

    /// Returns the actual address, including an OS-assigned port when bound to port zero.
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Accepts connections until shutdown and drains all bounded session tasks.
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
                    let services = self.services.clone();
                    let limits = self.limits;
                    let upstream = self.specification.upstream().clone();
                    let listener = self.local_address;
                    let session_shutdown = shutdown.clone();
                    sessions.spawn(async move {
                        let _permit = permit;
                        run_static_session(
                            client,
                            peer,
                            listener,
                            upstream,
                            services,
                            limits,
                            session_shutdown,
                        ).await
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
        let context = || AuditContext {
            occurred_at: UnixMillis::now(),
            session_id,
            transaction_id: None,
            policy_generation: self.services.policy().generation(),
        };
        self.services
            .publish(AuditEnvelope {
                context: context(),
                event: AuditEvent::ConnectionAccepted {
                    client: peer.to_string(),
                    listener: self.local_address.to_string(),
                },
            })
            .await?;
        self.services
            .publish(AuditEnvelope {
                context: context(),
                event: AuditEvent::FlowClosed {
                    client_to_upstream_bytes: 0,
                    upstream_to_client_bytes: 0,
                    outcome: "connection-limit".to_owned(),
                },
            })
            .await
    }
}

fn handle_join(
    joined: Option<Result<Result<(), ProxyError>, tokio::task::JoinError>>,
) -> Result<(), ProxyError> {
    match joined {
        Some(Ok(Ok(()))) | None => Ok(()),
        Some(Ok(Err(error))) => {
            warn!(error = %error, "static TCP session ended with an error");
            Ok(())
        }
        Some(Err(error)) => Err(ProxyError::Join(error)),
    }
}
