use std::{collections::BTreeSet, net::SocketAddr};

use freja_audit::{AuditContext, AuditEnvelope, AuditEvent, UnixMillis};
use freja_domain::{
    Decision, EnforcementAction, EvaluationTarget, ReplayFacts, RequestedTargetFacts,
    ResolvedTargetFacts, SessionId, TargetHost, TransactionId,
};
use freja_policy::PolicyFacts;
use tokio::{net::TcpStream, time::timeout};

use crate::{DataPlaneServices, ProxyError, ShutdownSignal, runtime::DecisionSnapshot};

pub(crate) async fn authorize_and_resolve(
    requested: &RequestedTargetFacts,
    services: &DataPlaneServices,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    resolution_timeout: std::time::Duration,
    shutdown: &mut ShutdownSignal,
) -> Result<Vec<SocketAddr>, ProxyError> {
    let snapshot = services.decision_snapshot();
    let selected =
        authorize_requested_target(requested, services, &snapshot, session_id, transaction_id)
            .await?;
    let addresses = resolve(&selected, resolution_timeout, shutdown).await?;
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, transaction_id, services),
            event: AuditEvent::TargetResolved {
                requested_host: selected.requested_host().as_host_text(),
                resolved_addresses: addresses.iter().map(SocketAddr::ip).collect(),
            },
        })
        .await?;

    authorize_resolved_targets(
        &selected,
        &addresses,
        services,
        &snapshot,
        session_id,
        transaction_id,
    )
    .await?;
    Ok(addresses)
}

async fn authorize_requested_target(
    requested: &RequestedTargetFacts,
    services: &DataPlaneServices,
    snapshot: &DecisionSnapshot,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
) -> Result<RequestedTargetFacts, ProxyError> {
    let mut selected = requested.clone();
    let mut detoured = false;
    loop {
        services
            .publish_replay_facts(
                audit_context(session_id, transaction_id, services),
                ReplayFacts::Requested(selected.clone()),
            )
            .await?;
        let requested_decision = snapshot
            .policy()
            .evaluate(PolicyFacts::Requested(&selected));
        services
            .publish_decision(
                audit_context(session_id, transaction_id, services),
                requested_decision.clone(),
                EvaluationTarget::Requested(selected.clone()),
            )
            .await?;
        let EnforcementAction::TcpDetour(detour) = &requested_decision.action else {
            if !snapshot.permits(&requested_decision) {
                record_action(
                    session_id,
                    transaction_id,
                    services,
                    requested_decision.clone(),
                )
                .await?;
                return Err(ProxyError::PolicyDenied {
                    decision: requested_decision,
                });
            }
            break;
        };
        if snapshot.permits(&requested_decision) {
            break;
        }
        record_action(
            session_id,
            transaction_id,
            services,
            requested_decision.clone(),
        )
        .await?;
        if detoured {
            return Err(ProxyError::DetourLoop {
                decision: requested_decision,
            });
        }
        selected = RequestedTargetFacts::new(
            selected.source_ip(),
            detour.destination.host().clone(),
            detour.destination.port(),
            selected.protocol(),
        );
        detoured = true;
    }
    Ok(selected)
}

async fn authorize_resolved_targets(
    selected: &RequestedTargetFacts,
    addresses: &[SocketAddr],
    services: &DataPlaneServices,
    snapshot: &DecisionSnapshot,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
) -> Result<(), ProxyError> {
    let mut first_denial = None;
    for address in addresses {
        let resolved = ResolvedTargetFacts::new(selected.clone(), address.ip());
        services
            .publish_replay_facts(
                audit_context(session_id, transaction_id, services),
                ReplayFacts::Resolved(resolved.clone()),
            )
            .await?;
        if let Some(decision) = snapshot
            .destination_guard()
            .evaluate(snapshot.policy().generation(), &resolved)
        {
            services
                .publish_decision(
                    audit_context(session_id, transaction_id, services),
                    decision.clone(),
                    EvaluationTarget::Resolved(resolved.clone()),
                )
                .await?;
            remember_denial(snapshot, &decision, &mut first_denial);
        }
        let decision = snapshot.policy().evaluate(PolicyFacts::Resolved(&resolved));
        services
            .publish_decision(
                audit_context(session_id, transaction_id, services),
                decision.clone(),
                EvaluationTarget::Resolved(resolved),
            )
            .await?;
        if matches!(decision.action, EnforcementAction::TcpDetour(_))
            && !snapshot.permits(&decision)
        {
            record_action(session_id, transaction_id, services, decision.clone()).await?;
            return Err(ProxyError::DetourLoop { decision });
        }
        remember_denial(snapshot, &decision, &mut first_denial);
    }
    if let Some(decision) = first_denial {
        record_action(session_id, transaction_id, services, decision.clone()).await?;
        return Err(ProxyError::PolicyDenied { decision });
    }
    Ok(())
}

pub(crate) async fn connect_any(
    addresses: &[SocketAddr],
    connect_timeout: std::time::Duration,
    shutdown: &mut ShutdownSignal,
) -> Result<(TcpStream, SocketAddr), ProxyError> {
    let mut last_error = None;
    for address in addresses {
        let attempt = timeout(connect_timeout, TcpStream::connect(*address));
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
            result = attempt => result,
        };
        match outcome {
            Ok(Ok(stream)) => return Ok((stream, *address)),
            Ok(Err(source)) => {
                last_error = Some(ProxyError::ConnectFailed {
                    target: *address,
                    source,
                });
            }
            Err(_) => {
                last_error = Some(ProxyError::ConnectTimedOut { target: *address });
            }
        }
    }
    let Some(error) = last_error else {
        return Err(ProxyError::NoResolvedAddresses {
            host: "<empty address set>".to_owned(),
        });
    };
    Err(error)
}

pub(crate) async fn record_action(
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    services: &DataPlaneServices,
    decision: Decision,
) -> Result<(), ProxyError> {
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, transaction_id, services),
            event: AuditEvent::ActionExecuted { decision },
        })
        .await
}

pub(crate) fn audit_context(
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    services: &DataPlaneServices,
) -> AuditContext {
    AuditContext {
        occurred_at: UnixMillis::now(),
        session_id,
        transaction_id,
        policy_generation: services.policy().generation(),
    }
}

async fn resolve(
    requested: &RequestedTargetFacts,
    resolution_timeout: std::time::Duration,
    shutdown: &mut ShutdownSignal,
) -> Result<Vec<SocketAddr>, ProxyError> {
    let port = requested.destination_port().get();
    let addresses = match requested.requested_host() {
        TargetHost::Ip(address) => vec![SocketAddr::new(*address, port)],
        TargetHost::Name(host) => {
            let lookup = timeout(
                resolution_timeout,
                tokio::net::lookup_host((host.as_str(), port)),
            );
            let resolved = tokio::select! {
                () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
                result = lookup => match result {
                    Ok(Ok(resolved)) => resolved,
                    Ok(Err(source)) => return Err(ProxyError::Dns {
                        host: host.as_str().to_owned(),
                        source,
                    }),
                    Err(_) => return Err(ProxyError::DnsTimedOut {
                        host: host.as_str().to_owned(),
                    }),
                },
            };
            resolved.collect()
        }
    };
    let addresses = addresses.into_iter().collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        return Err(ProxyError::NoResolvedAddresses {
            host: requested.requested_host().as_host_text(),
        });
    }
    Ok(addresses.into_iter().collect())
}

fn remember_denial(
    snapshot: &crate::runtime::DecisionSnapshot,
    decision: &Decision,
    first_denial: &mut Option<Decision>,
) {
    if !snapshot.permits(decision) && first_denial.is_none() {
        *first_denial = Some(decision.clone());
    }
}
