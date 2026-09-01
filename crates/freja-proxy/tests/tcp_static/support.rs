use super::*;

pub(super) fn limits() -> ProxyLimits {
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
pub(super) struct DroppingEventSink {
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

pub(super) fn inspection_services(
    upstream_rules: Vec<AclRule>,
    enforcement: EnforcementMode,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    inspection_services_with_mode(upstream_rules, enforcement, InspectionMode::Streaming)
}

pub(super) fn inspection_services_with_mode(
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

pub(super) fn services(
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

pub(super) fn local_access() -> DestinationGuardSettings {
    DestinationGuardSettings {
        loopback: DestinationAccess::Allow,
        ..DestinationGuardSettings::default()
    }
}

pub(super) async fn spawn_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

pub(super) async fn spawn_recording_echo_server()
-> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
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

pub(super) async fn spawn_multi_echo_server(
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

pub(super) fn tcp_spec(host: TargetHost, port: u16) -> TcpStaticListener {
    TcpStaticListener::new(
        ListenEndpoint::new((IpAddr::from([127, 0, 0, 1]), 0).into()),
        UpstreamEndpoint::new(host, Port::new(port).unwrap()),
    )
}

pub(super) async fn stop_server(
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

pub(super) fn collect_events(receiver: &mut mpsc::Receiver<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}
