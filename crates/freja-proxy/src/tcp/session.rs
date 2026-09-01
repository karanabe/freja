use std::net::SocketAddr;

use freja_audit::{AuditEnvelope, AuditEvent};
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
        Ok(relay) => (relay.stats, termination_name(relay.termination)),
        Err(error) => (RelayStats::default(), error_outcome(error)),
    };
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, None, &services),
            event: AuditEvent::FlowClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome: outcome.to_owned(),
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

const fn termination_name(termination: RelayTermination) -> &'static str {
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
        ProxyError::Dns { .. } | ProxyError::NoResolvedAddresses { .. } => "dns-failure",
        ProxyError::DnsTimedOut { .. } => "dns-timeout",
        ProxyError::ConnectFailed { .. } => "connect-failure",
        ProxyError::ConnectTimedOut { .. } => "connect-timeout",
        ProxyError::RelayRead { .. } | ProxyError::RelayWrite { .. } => "relay-failure",
        ProxyError::Audit(_) => "audit-failure",
        ProxyError::Hook(_)
        | ProxyError::HookMutation(_)
        | ProxyError::Interactive(_)
        | ProxyError::InteractiveRejected => "hook-failure",
        ProxyError::Shutdown => "shutdown",
        ProxyError::Bind { .. }
        | ProxyError::LocalAddress(_)
        | ProxyError::Accept(_)
        | ProxyError::HttpConnection(_)
        | ProxyError::UpstreamHttp { .. }
        | ProxyError::UpstreamResponseTimedOut
        | ProxyError::HttpUpgrade(_)
        | ProxyError::TunnelRegistration
        | ProxyError::InternalPolicy(_)
        | ProxyError::ConcurrencyClosed
        | ProxyError::Join(_)
        | ProxyError::Socks(_)
        | ProxyError::Tls(_) => "runtime-failure",
    }
}
