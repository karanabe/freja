use std::net::SocketAddr;

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{
    Decision, DecisionTrace, EnforcementAction, EvaluationTarget, HttpReject, MatchReason,
    PolicyStage, Protocol, RequestedTargetFacts, ResolvedTargetFacts, SessionId, TransactionId,
};
use http::{Method, Request, Response, StatusCode};
use hyper::{body::Incoming, upgrade::OnUpgrade};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::{
    ConnectionTaskHandle, DataPlaneServices, FlowInspector, ForwardTarget, HttpService, ProxyBody,
    ProxyError, RelayLimits, RelayStats, RelayTermination, ShutdownSignal, audit_context,
    authorize_and_resolve, connect_any, headers,
    intercept::run_intercepted_tunnel,
    record_action, relay,
    response::{response_for_error, text_response},
};

impl HttpService {
    pub(super) async fn connect(
        &self,
        mut request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if let Err(error) = headers::validate(request.headers(), self.limits.header_bytes) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        self.apply_request_head_hooks(transaction_id, &mut request)
            .await?;
        self.pause_connect_request(transaction_id, &mut request)
            .await?;
        let target = match ForwardTarget::from_connect(request.uri()) {
            Ok(target) => target,
            Err(error) => return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
        };
        if !self.connect_ports.allows_connect_port(target.port()) {
            let snapshot = self.services.decision_snapshot();
            let decision = self.connect_port_denial(target.port(), &snapshot);
            self.services
                .publish_decision(
                    audit_context(self.session_id, Some(transaction_id), &self.services),
                    decision.clone(),
                    (
                        freja_policy::evidence::RuleDefinition::ConnectPorts(
                            self.connect_ports.connect_ports(),
                        ),
                        snapshot.enforcement(),
                    ),
                    EvaluationTarget::Requested(RequestedTargetFacts::new(
                        self.peer.ip(),
                        target.host().clone(),
                        target.port(),
                        Protocol::Http,
                    )),
                )
                .await?;
            if !snapshot.permits(&decision) {
                record_action(
                    self.session_id,
                    Some(transaction_id),
                    &self.services,
                    decision.clone(),
                )
                .await?;
                return response_for_error(ProxyError::PolicyDenied { decision });
            }
        }

        let requested = RequestedTargetFacts::new(
            self.peer.ip(),
            target.host().clone(),
            target.port(),
            Protocol::Http,
        );
        let mut shutdown = self.shutdown.clone();
        let addresses = match authorize_and_resolve(
            &requested,
            &self.services,
            self.session_id,
            Some(transaction_id),
            self.limits.connect_timeout,
            &mut shutdown,
        )
        .await
        {
            Ok(addresses) => addresses,
            Err(error) => return response_for_error(error),
        };
        if let Some(response) = self
            .evaluate_http_policy(
                &requested,
                &addresses,
                transaction_id,
                Method::CONNECT.as_str(),
                target.authority(),
                request.headers(),
            )
            .await?
        {
            return Ok(response);
        }
        let (upstream, selected_address) =
            match connect_any(&addresses, self.limits.connect_timeout, &mut shutdown).await {
                Ok(connected) => connected,
                Err(error) => return response_for_error(error),
            };

        let on_upgrade = hyper::upgrade::on(&mut request);
        let handle = self
            .start_connect_tunnel(
                on_upgrade,
                upstream,
                selected_address,
                &target,
                transaction_id,
            )
            .await?;
        self.register_task(handle).await?;
        if let Some(capture) = &self.request_capture {
            capture.disable();
        }
        Ok(text_response(StatusCode::OK, ""))
    }

    pub(super) async fn start_connect_tunnel(
        &self,
        on_upgrade: OnUpgrade,
        upstream: TcpStream,
        selected_address: SocketAddr,
        target: &ForwardTarget,
        transaction_id: TransactionId,
    ) -> Result<ConnectionTaskHandle, ProxyError> {
        let services = self.services.clone();
        let session_id = self.session_id;
        let tunnel_shutdown = self.shutdown.clone();
        let idle_timeout = self.limits.idle_timeout;
        let relay_limits = RelayLimits::new(
            self.limits.idle_timeout,
            self.limits.body_prefix_bytes,
            self.limits.read_timeout,
        );
        let handle = if let Some(interceptor) = self.services.tls_interceptor()
            && interceptor.should_intercept(target.host())
        {
            let (acceptor, cache_hit) = interceptor
                .downstream_acceptor(target.host(), None)
                .map_err(ProxyError::Tls)?;
            services
                .publish(AuditEnvelope {
                    context: audit_context(session_id, Some(transaction_id), &services),
                    event: AuditEvent::TlsCertificateGenerated {
                        hostname: target.host().to_string(),
                        cache_hit,
                    },
                })
                .await?;
            tokio::spawn(run_intercepted_tunnel(
                on_upgrade,
                upstream,
                acceptor,
                interceptor,
                target.clone(),
                selected_address,
                self.clone(),
                services,
                session_id,
                transaction_id,
                self.limits.connect_timeout,
                idle_timeout,
                tunnel_shutdown,
            ))
        } else {
            tokio::spawn(run_tunnel(
                on_upgrade,
                upstream,
                services,
                session_id,
                transaction_id,
                ResolvedTargetFacts::new(
                    RequestedTargetFacts::new(
                        self.peer.ip(),
                        target.host().clone(),
                        target.port(),
                        Protocol::Http,
                    ),
                    selected_address.ip(),
                ),
                relay_limits,
                tunnel_shutdown,
            ))
        };
        Ok(handle)
    }

    pub(super) fn connect_port_denial(
        &self,
        port: freja_domain::Port,
        snapshot: &crate::runtime::DecisionSnapshot,
    ) -> Decision {
        let action = EnforcementAction::HttpReject(HttpReject::Forbidden);
        Decision {
            trace: DecisionTrace {
                policy_generation: snapshot.policy().generation(),
                evaluated_stage: PolicyStage::HttpRequest,
                matched_rule: Some(self.connect_port_rule.clone()),
                match_reasons: vec![MatchReason {
                    criterion: "connect-port-allowlist".to_owned(),
                    observed: port.to_string(),
                }],
                final_action: action.kind(),
            },
            action,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    on_upgrade: OnUpgrade,
    upstream: tokio::net::TcpStream,
    services: DataPlaneServices,
    session_id: SessionId,
    transaction_id: TransactionId,
    target: ResolvedTargetFacts,
    relay_limits: RelayLimits,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError> {
    let upgraded = tokio::select! {
        () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
        result = on_upgrade => result.map_err(ProxyError::HttpUpgrade)?,
    };
    let inspection = FlowInspector::new(
        services.clone(),
        session_id,
        Some(transaction_id),
        Protocol::Tcp,
        relay_limits.inspection_bytes(),
    )
    .with_target(target);
    let result = relay(
        TokioIo::new(upgraded),
        upstream,
        relay_limits,
        shutdown,
        Some(inspection),
    )
    .await;
    let (stats, outcome) = match &result {
        Ok(relay) => (relay.stats, tunnel_outcome(relay.termination)),
        Err(error) => (RelayStats::default(), tunnel_error_outcome(error)),
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
    result.map(|_| ())
}
const fn tunnel_outcome(termination: RelayTermination) -> &'static str {
    match termination {
        RelayTermination::Completed => "completed",
        RelayTermination::IdleTimeout => "idle-timeout",
        RelayTermination::Shutdown => "shutdown",
        RelayTermination::InspectionBlocked => "inspection-blocked",
    }
}

pub(super) const fn tunnel_error_outcome(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::RelayRead { .. } | ProxyError::RelayWrite { .. } => "relay-failure",
        ProxyError::Shutdown => "shutdown",
        _ => "tunnel-failure",
    }
}
