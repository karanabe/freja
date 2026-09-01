use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_domain::{
    Confidence, DetectorId, Direction, EnforcementAction, EnforcementMode, HookMode, HostName,
    InspectionMode, ListenEndpoint, PolicyGeneration, Port, Protocol, RuleId, Severity, TargetHost,
    TcpStaticListener, UpstreamEndpoint,
};
use freja_policy::{
    AclPolicy, AclRule, DestinationAccess, DestinationGuard, DestinationGuardSettings, HostPattern,
    InspectionPattern, InspectionProgram, MatchExpression, PortRange, RuleAction,
    hook::{
        ChunkMutationPlan, HookFailurePolicy, HookFuture, HookRegistry, HookRunner,
        TcpClientChunkHook,
    },
};
use freja_proxy::{
    DataPlaneEvent, DataPlaneEventSink, DataPlaneServices, ProxyLimits, StaticTcpServer,
    shutdown_channel,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

fn limits() -> ProxyLimits {
    ProxyLimits::new(
        8,
        16 * 1_024,
        16 * 1_024,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap()
}

#[derive(Debug, Clone, Default)]
struct DroppingEventSink {
    dropped: Arc<AtomicU64>,
}

impl DataPlaneEventSink for DroppingEventSink {
    fn try_publish(&self, _event: DataPlaneEvent) {
        let _previous = self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

fn inspection_services(
    upstream_rules: Vec<AclRule>,
    enforcement: EnforcementMode,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    inspection_services_with_mode(upstream_rules, enforcement, InspectionMode::Streaming)
}

fn inspection_services_with_mode(
    upstream_rules: Vec<AclRule>,
    enforcement: EnforcementMode,
    mode: InspectionMode,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    let generation = PolicyGeneration::new(14).unwrap();
    let policy = AclPolicy::new(generation, upstream_rules, RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let detector = InspectionPattern::new(
        DetectorId::new("split-signature").unwrap(),
        RuleId::new("block-split-signature").unwrap(),
        b"MALWARE".to_vec(),
        Severity::High,
        Confidence::Confirmed,
        vec![Direction::ClientToUpstream],
        RuleAction::Deny,
        vec!["test-signature".to_owned()],
    )
    .unwrap();
    let inspection = InspectionProgram::new(generation, vec![detector]).unwrap();
    let (audit, receiver) = AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    (
        DataPlaneServices::new(policy, guard, enforcement, audit).with_inspection(inspection, mode),
        receiver,
    )
}

fn services(
    rules: Vec<AclRule>,
    guard_settings: DestinationGuardSettings,
    generation: u64,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    let policy = AclPolicy::new(
        PolicyGeneration::new(generation).unwrap(),
        rules,
        RuleAction::Allow,
    )
    .unwrap();
    let guard = DestinationGuard::new(guard_settings).unwrap();
    let (audit, receiver) = AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    (
        DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit),
        receiver,
    )
}

fn local_access() -> DestinationGuardSettings {
    DestinationGuardSettings {
        loopback: DestinationAccess::Allow,
        ..DestinationGuardSettings::default()
    }
}

async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1_024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count]).await.unwrap();
        }
    });
    (address, task)
}

async fn spawn_recording_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0_u8; 1_024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&buffer[..count]);
            stream.write_all(&buffer[..count]).await.unwrap();
        }
        received
    });
    (address, task)
}

async fn spawn_multi_echo_server(
    connections: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        for _ in 0..connections {
            let (mut stream, _) = listener.accept().await.unwrap();
            sessions.spawn(async move {
                let mut buffer = [0_u8; 1_024];
                loop {
                    let count = stream.read(&mut buffer).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    stream.write_all(&buffer[..count]).await.unwrap();
                }
            });
        }
        while let Some(result) = sessions.join_next().await {
            result.unwrap();
        }
    });
    (address, task)
}

fn tcp_spec(host: TargetHost, port: u16) -> TcpStaticListener {
    TcpStaticListener::new(
        ListenEndpoint::new((IpAddr::from([127, 0, 0, 1]), 0).into()),
        UpstreamEndpoint::new(host, Port::new(port).unwrap()),
    )
}

async fn stop_server(
    shutdown: freja_proxy::ShutdownSender,
    task: tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    shutdown.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

fn collect_events(receiver: &mut mpsc::Receiver<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn allowed_static_tcp_connection_relays_bytes_and_audits_counts() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, mut audit) = services(Vec::new(), local_access(), 11);
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client.write_all(b"freja").await.unwrap();
    let mut response = [0_u8; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"freja");
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .all(|event| event.context.policy_generation.get() == 11)
    );
    assert!(events.iter().any(|event| matches!(
        event.event,
        AuditEvent::FlowClosed {
            client_to_upstream_bytes: 5,
            upstream_to_client_bytes: 5,
            ..
        }
    )));
}

#[tokio::test]
async fn requested_destination_denial_closes_before_upstream_connect() {
    let denied_port = Port::new(9).unwrap();
    let rule = AclRule {
        id: RuleId::new("deny-test-port").unwrap(),
        matcher: MatchExpression::DestinationPort(
            PortRange::new(denied_port, denied_port).unwrap(),
        ),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![rule], local_access(), 12);
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(IpAddr::from([127, 0, 0, 1])), 9),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str) == Some("deny-test-port")
    )));
}

#[tokio::test]
async fn tcp_detour_reselects_and_reauthorizes_the_upstream_before_relay() {
    let original = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let original_address = original.local_addr().unwrap();
    let (detour, echo_task) = spawn_echo_server().await;
    let detour_rule = AclRule {
        id: RuleId::new("detour-test-port").unwrap(),
        matcher: MatchExpression::All(vec![
            MatchExpression::Protocol(Protocol::Tcp),
            MatchExpression::DestinationPort(
                PortRange::new(
                    Port::new(original_address.port()).unwrap(),
                    Port::new(original_address.port()).unwrap(),
                )
                .unwrap(),
            ),
        ]),
        action: RuleAction::Detour(UpstreamEndpoint::new(
            TargetHost::Ip(detour.ip()),
            Port::new(detour.port()).unwrap(),
        )),
    };
    let (services, mut audit) = services(vec![detour_rule], local_access(), 15);
    let server = StaticTcpServer::bind(
        tcp_spec(
            TargetHost::Ip(original_address.ip()),
            original_address.port(),
        ),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client.write_all(b"detour").await.unwrap();
    let mut response = [0_u8; 6];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"detour");
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;
    drop(original);

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if matches!(decision.action, EnforcementAction::TcpDetour(_))
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ReplayFactsObserved {
            facts: freja_domain::ReplayFacts::Requested(facts),
        } if facts.destination_port().get() == detour.port()
    )));
}

#[tokio::test]
async fn allowed_hostname_is_denied_after_it_resolves_to_loopback() {
    let allow_hostname = AclRule {
        id: RuleId::new("allow-localhost-name").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("localhost").unwrap(),
        )),
        action: RuleAction::Allow,
    };
    let (services, mut audit) = services(
        vec![allow_hostname],
        DestinationGuardSettings::default(),
        13,
    );
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Name(HostName::new("localhost").unwrap()), 9),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    let resolved_count = events.iter().find_map(|event| match &event.event {
        AuditEvent::TargetResolved {
            resolved_addresses, ..
        } => Some(resolved_addresses.len()),
        _ => None,
    });
    assert!(resolved_count.is_some_and(|count| count >= 1));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("protect-loopback-destination")
    )));
}

#[tokio::test]
async fn split_pattern_is_observed_without_blocking_in_observe_mode() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, mut audit) = inspection_services(Vec::new(), EnforcementMode::Observe);
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"MAL").await.unwrap();
    let mut first = [0_u8; 3];
    client.read_exact(&mut first).await.unwrap();
    client.write_all(b"WARE").await.unwrap();
    let mut second = [0_u8; 4];
    client.read_exact(&mut second).await.unwrap();
    assert_eq!([first.as_slice(), second.as_slice()].concat(), b"MALWARE");
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::FindingDetected { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::ActionExecuted { .. }))
    );
}

#[tokio::test]
async fn split_pattern_closes_flow_before_matched_chunk_in_enforce_mode() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, mut audit) = inspection_services(Vec::new(), EnforcementMode::Enforce);
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"MAL").await.unwrap();
    let mut first = [0_u8; 3];
    client.read_exact(&mut first).await.unwrap();
    client.write_all(b"WARE").await.unwrap();
    let mut blocked = [0_u8; 4];
    let count = timeout(Duration::from_secs(1), client.read(&mut blocked))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("block-split-signature")
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FlowClosed { outcome, .. } if outcome == "inspection-blocked"
    )));
}

#[tokio::test]
async fn tcp_preflight_blocks_split_pattern_before_forwarding_any_bytes() {
    let (upstream, upstream_task) = spawn_recording_echo_server().await;
    let (services, mut audit) = inspection_services_with_mode(
        Vec::new(),
        EnforcementMode::Enforce,
        InspectionMode::Preflight,
    );
    let preflight_limits = limits().with_body_prefix_bytes(b"MALWARE".len()).unwrap();
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        preflight_limits,
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"MAL").await.unwrap();
    let mut first = [0_u8; 3];
    assert!(
        timeout(Duration::from_millis(50), client.read(&mut first))
            .await
            .is_err()
    );
    client.write_all(b"WARE").await.unwrap();
    let count = timeout(Duration::from_secs(1), client.read(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count, 0);
    assert!(upstream_task.await.unwrap().is_empty());
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("block-split-signature")
    )));
}

#[tokio::test]
async fn tcp_preflight_releases_a_benign_short_prefix_after_timeout() {
    let (upstream, upstream_task) = spawn_recording_echo_server().await;
    let (services, _audit) = inspection_services_with_mode(
        Vec::new(),
        EnforcementMode::Enforce,
        InspectionMode::Preflight,
    );
    let preflight_limits = limits()
        .with_body_prefix_bytes(b"MALWARE".len())
        .unwrap()
        .with_read_timeout(Duration::from_millis(25))
        .unwrap();
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        preflight_limits,
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"OK").await.unwrap();
    let mut response = [0_u8; 2];
    timeout(Duration::from_secs(1), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"OK");
    client.write_all(b"MALWARE").await.unwrap();
    let mut later = [0_u8; 7];
    timeout(Duration::from_secs(1), client.read_exact(&mut later))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&later, b"MALWARE");
    drop(client);
    assert_eq!(upstream_task.await.unwrap(), b"OKMALWARE");
    stop_server(shutdown, server_task).await;
}

#[tokio::test]
async fn tcp_streaming_inspection_stops_at_the_configured_prefix_budget() {
    let (upstream, upstream_task) = spawn_recording_echo_server().await;
    let (services, _audit) = inspection_services(Vec::new(), EnforcementMode::Enforce);
    let bounded_limits = limits().with_body_prefix_bytes(4).unwrap();
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        bounded_limits,
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"OKOKMALWARE").await.unwrap();
    let mut response = [0_u8; 11];
    timeout(Duration::from_secs(1), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"OKOKMALWARE");

    drop(client);
    assert_eq!(upstream_task.await.unwrap(), b"OKOKMALWARE");
    stop_server(shutdown, server_task).await;
}

#[tokio::test]
async fn dropping_event_sink_does_not_block_tcp_forwarding() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, _audit) = services(Vec::new(), local_access(), 15);
    let sink = DroppingEventSink::default();
    let metrics = services.clone().with_event_sink(sink.clone());
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        metrics.clone(),
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"still-forwarding").await.unwrap();
    let mut response = [0_u8; 16];
    timeout(Duration::from_secs(1), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"still-forwarding");
    assert!(sink.dropped_events() > 0);
    assert!(metrics.metrics_snapshot().event_sink_dropped_events > 0);
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;
}

#[tokio::test]
async fn connection_limit_rejects_excess_load_and_recovers_capacity() {
    let (upstream, echo_task) = spawn_multi_echo_server(5).await;
    let (services, mut audit) = services(Vec::new(), local_access(), 17);
    let metrics = services.clone();
    let constrained = limits().with_connections(4).unwrap();
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services,
        constrained,
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut active = Vec::new();
    for value in 0_u8..4 {
        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(&[value]).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), value);
        active.push(client);
    }
    let mut excess = TcpStream::connect(proxy_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), excess.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    drop(excess);

    drop(active.remove(0));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut replacement = TcpStream::connect(proxy_address).await.unwrap();
    replacement.write_all(b"R").await.unwrap();
    assert_eq!(replacement.read_u8().await.unwrap(), b'R');
    drop(replacement);
    drop(active);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    assert_eq!(metrics.metrics_snapshot().active_flows, 0);
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FlowClosed { outcome, .. } if outcome == "connection-limit"
    )));
}

struct ReplaceClientChunk;

impl TcpClientChunkHook for ReplaceClientChunk {
    fn call<'a>(&'a self, input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan> {
        let replacement = if input.as_ref() == b"before" {
            Bytes::from_static(b"after")
        } else {
            input.clone()
        };
        Box::pin(async move { Ok(ChunkMutationPlan::Replace(replacement)) })
    }
}

struct OversizedClientChunk;

impl TcpClientChunkHook for OversizedClientChunk {
    fn call<'a>(&'a self, _input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan> {
        Box::pin(async { Ok(ChunkMutationPlan::Replace(Bytes::from_static(b"12345"))) })
    }
}

#[tokio::test]
async fn automatic_tcp_hook_transforms_chunk_and_emits_audit_event() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, mut audit) = services(Vec::new(), local_access(), 16);
    let mut registry = HookRegistry::default();
    registry.register_tcp_client(Arc::new(ReplaceClientChunk));
    let hooks = HookRunner::new(
        HookMode::Automatic,
        registry,
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services.with_hooks(hooks),
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"before").await.unwrap();
    let mut response = [0_u8; 5];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"after");
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HookExecuted { stage, outcome }
            if stage == "tcp-client-chunk" && outcome == "completed"
    )));
}

#[tokio::test]
async fn tcp_hook_replacement_respects_the_configured_body_budget() {
    let (upstream, echo_task) = spawn_echo_server().await;
    let (services, mut audit) = services(Vec::new(), local_access(), 16);
    let mut registry = HookRegistry::default();
    registry.register_tcp_client(Arc::new(OversizedClientChunk));
    let hooks = HookRunner::new(
        HookMode::Automatic,
        registry,
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let bounded_limits = limits().with_body_prefix_bytes(4).unwrap();
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(upstream.ip()), upstream.port()),
        services.with_hooks(hooks),
        bounded_limits,
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));
    let mut client = TcpStream::connect(proxy_address).await.unwrap();

    client.write_all(b"x").await.unwrap();
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FlowClosed { outcome, .. } if outcome == "hook-failure"
    )));
}
