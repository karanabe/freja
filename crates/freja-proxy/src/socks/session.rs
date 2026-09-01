use super::protocol::{negotiate_authentication, read_request, reply_for_proxy_error, send_reply};
use std::net::SocketAddr;

use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{Protocol, ProxyCredentialHash, RequestedTargetFacts, SessionId};
use tokio::net::TcpStream;

use super::{
    DataPlaneServices, FlowInspector, ProxyError, ProxyLimits, RelayLimits, RelayStats,
    RelayTermination, ShutdownSignal, SocksError, audit_context, authorize_and_resolve,
    connect_any, relay,
};

pub(super) struct SessionContext {
    pub(super) peer: SocketAddr,
    pub(super) listener: SocketAddr,
    pub(super) authentication: Option<ProxyCredentialHash>,
    pub(super) services: DataPlaneServices,
    pub(super) limits: ProxyLimits,
    pub(super) shutdown: ShutdownSignal,
}

pub(super) async fn serve_session(
    mut client: TcpStream,
    context: SessionContext,
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
