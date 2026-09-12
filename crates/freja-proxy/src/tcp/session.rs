use std::net::SocketAddr;

use freja_audit::{AuditEnvelope, AuditEvent, FlowOutcome};
use freja_domain::{Protocol, RequestedTargetFacts, SessionId, UpstreamEndpoint};
use tokio::net::TcpStream;

use super::relay::{RelayLimits, RelayResult, RelayStats, RelayTermination, relay};
use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any},
    inspection::FlowInspector,
};

pub(super) async fn run_static_session(
    client: TcpStream,
    peer: SocketAddr,
    listener: SocketAddr,
    upstream: UpstreamEndpoint,
    services: DataPlaneServices,
    limits: ProxyLimits,
    shutdown: ShutdownSignal,
) -> Result<(), ProxyError> {
    let session_id = SessionId::new();
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &services),
            event: AuditEvent::ConnectionAccepted {
                client: peer.to_string(),
                listener: listener.to_string(),
            },
        })
        .await?;
    services.publish_flow_opened(session_id, peer.to_string(), upstream.to_string());

    let result = run_session_inner(
        client, peer, &upstream, session_id, &services, limits, shutdown,
    )
    .await;
    let (stats, outcome) = match &result {
        Ok(relay) => (relay.stats, termination_outcome(relay.termination)),
        Err(error) => (RelayStats::default(), error_outcome(error)),
    };
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &services),
            event: AuditEvent::FlowClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome,
            },
        })
        .await?;
    services.publish_flow_closed(
        session_id,
        stats.client_to_upstream_bytes,
        stats.upstream_to_client_bytes,
    );
    result.map(|_| ())
}

async fn run_session_inner(
    client: TcpStream,
    peer: SocketAddr,
    upstream: &UpstreamEndpoint,
    session_id: SessionId,
    services: &DataPlaneServices,
    limits: ProxyLimits,
    mut shutdown: ShutdownSignal,
) -> Result<RelayResult, ProxyError> {
    let requested = RequestedTargetFacts::new(
        peer.ip(),
        upstream.host().clone(),
        upstream.port(),
        Protocol::Tcp,
    );
    let addresses = authorize_and_resolve(
        &requested,
        services,
        session_id,
        None,
        limits.connect_timeout,
        &mut shutdown,
    )
    .await?;
    let (upstream_stream, _selected_address) =
        connect_any(&addresses, limits.connect_timeout, &mut shutdown).await?;
    let inspection = FlowInspector::new(
        services.clone(),
        session_id,
        None,
        Protocol::Tcp,
        limits.body_prefix_bytes,
    );
    relay(
        client,
        upstream_stream,
        RelayLimits::new(
            limits.idle_timeout,
            limits.body_prefix_bytes,
            limits.read_timeout,
        ),
        shutdown,
        Some(inspection),
    )
    .await
}

const fn termination_outcome(termination: RelayTermination) -> FlowOutcome {
    match termination {
        RelayTermination::Completed => FlowOutcome::Completed,
        RelayTermination::IdleTimeout => FlowOutcome::IdleTimeout,
        RelayTermination::Shutdown => FlowOutcome::Shutdown,
        RelayTermination::InspectionBlocked => FlowOutcome::InspectionBlocked,
    }
}

const fn error_outcome(error: &ProxyError) -> FlowOutcome {
    match error {
        ProxyError::PolicyDenied { .. } => FlowOutcome::PolicyDenied,
        ProxyError::DetourLoop { .. } => FlowOutcome::DetourLoop,
        ProxyError::Dns { .. } | ProxyError::NoResolvedAddresses { .. } => FlowOutcome::DnsFailure,
        ProxyError::DnsTimedOut { .. } => FlowOutcome::DnsTimeout,
        ProxyError::ConnectFailed { .. } => FlowOutcome::ConnectFailure,
        ProxyError::ConnectTimedOut { .. } => FlowOutcome::ConnectTimeout,
        ProxyError::RelayRead { .. } | ProxyError::RelayWrite { .. } => FlowOutcome::RelayFailure,
        ProxyError::Audit(_) => FlowOutcome::AuditFailure,
        ProxyError::Hook(_)
        | ProxyError::HookMutation(_)
        | ProxyError::Interactive(_)
        | ProxyError::InteractiveRejected => FlowOutcome::HookFailure,
        ProxyError::Shutdown => FlowOutcome::Shutdown,
        ProxyError::Bind { .. }
        | ProxyError::LocalAddress(_)
        | ProxyError::Accept(_)
        | ProxyError::HttpConnection(_)
        | ProxyError::UpstreamHttp { .. }
        | ProxyError::InvalidHttpStatus(_)
        | ProxyError::UpstreamResponseTimedOut
        | ProxyError::HttpUpgrade(_)
        | ProxyError::TunnelRegistration
        | ProxyError::InternalPolicy(_)
        | ProxyError::ConcurrencyClosed
        | ProxyError::Join(_)
        | ProxyError::Socks(_)
        | ProxyError::Tls(_) => FlowOutcome::RuntimeFailure,
    }
}
