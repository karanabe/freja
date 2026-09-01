use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct RecordingEventSink {
    events: Arc<Mutex<Vec<DataPlaneEvent>>>,
}

impl RecordingEventSink {
    pub(super) fn events(&self) -> Vec<DataPlaneEvent> {
        match self.events.lock() {
            Ok(events) => events.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl DataPlaneEventSink for RecordingEventSink {
    fn try_publish(&self, event: DataPlaneEvent) {
        match self.events.lock() {
            Ok(mut events) => events.push(event),
            Err(poisoned) => poisoned.into_inner().push(event),
        }
    }

    fn dropped_events(&self) -> u64 {
        0
    }
}

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

pub(super) fn inspected_services(
    direction: Direction,
    enforcement: EnforcementMode,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    let generation = PolicyGeneration::new(31).unwrap();
    let pattern = InspectionPattern::new(
        DetectorId::new("http-body-signature").unwrap(),
        RuleId::new("block-http-body-signature").unwrap(),
        b"MALWARE".to_vec(),
        Severity::High,
        Confidence::Confirmed,
        vec![direction],
        RuleAction::Deny,
        vec!["http-body".to_owned()],
    )
    .unwrap();
    let program = InspectionProgram::new(generation, vec![pattern]).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit, receiver) = AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    (
        DataPlaneServices::new(policy, guard, enforcement, audit)
            .with_inspection(program, InspectionMode::Preflight),
        receiver,
    )
}

pub(super) fn services(
    rules: Vec<AclRule>,
    guard_settings: DestinationGuardSettings,
) -> (DataPlaneServices, mpsc::Receiver<AuditEnvelope>) {
    let policy =
        AclPolicy::new(PolicyGeneration::new(31).unwrap(), rules, RuleAction::Allow).unwrap();
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

pub(super) async fn bind_proxy(
    connect_ports: Vec<Port>,
    services: DataPlaneServices,
) -> (
    std::net::SocketAddr,
    freja_proxy::ShutdownSender,
    tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    bind_proxy_with_limits(connect_ports, services, limits()).await
}

pub(super) async fn bind_proxy_with_limits(
    connect_ports: Vec<Port>,
    services: DataPlaneServices,
    limits: ProxyLimits,
) -> (
    std::net::SocketAddr,
    freja_proxy::ShutdownSender,
    tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    let specification = HttpForwardListener::with_connect_ports(
        ListenEndpoint::new((IpAddr::from([127, 0, 0, 1]), 0).into()),
        connect_ports,
    )
    .unwrap();
    let server = HttpForwardServer::bind(specification, services, limits)
        .await
        .unwrap();
    let address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    (address, shutdown, tokio::spawn(server.run(signal)))
}

pub(super) async fn bind_proxy_with_authentication(
    authentication: ProxyAuthentication,
    services: DataPlaneServices,
) -> (
    std::net::SocketAddr,
    freja_proxy::ShutdownSender,
    tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    let specification = HttpForwardListener::new(ListenEndpoint::new(
        (IpAddr::from([127, 0, 0, 1]), 0).into(),
    ))
    .with_authentication(authentication);
    let server = HttpForwardServer::bind(specification, services, limits())
        .await
        .unwrap();
    let address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    (address, shutdown, tokio::spawn(server.run(signal)))
}

pub(super) async fn stop_proxy(
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

pub(super) async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() < 64 * 1_024);
    }
    bytes
}

pub(super) async fn spawn_origin() -> (
    std::net::SocketAddr,
    oneshot::Receiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (request_sender, request_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let head = read_head(&mut stream).await;
        request_sender
            .send(String::from_utf8_lossy(&head).into_owned())
            .unwrap();
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\nX-Upstream: yes\r\n\r\nhello",
            )
            .await
            .unwrap();
    });
    (address, request_receiver, task)
}

pub(super) async fn spawn_fixed_origin(
    response: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _request = read_head(&mut stream).await;
        stream.write_all(response).await.unwrap();
    });
    (address, task)
}

pub(super) async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 64];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            stream.write_all(&buffer[..count]).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });
    (address, task)
}

pub(super) fn test_ca() -> (CertifiedIssuer<'static, KeyPair>, String) {
    let key = KeyPair::generate().unwrap();
    let key_pem = key.serialize_pem();
    let mut parameters = CertificateParams::default();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    parameters.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    (
        CertifiedIssuer::self_signed(parameters, key).unwrap(),
        key_pem,
    )
}

pub(super) async fn spawn_tls_http1(
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let leaf_key = KeyPair::generate().unwrap();
    let parameters = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let leaf = parameters.signed_by(&leaf_key, issuer).unwrap();
    let chain = vec![leaf.der().clone(), issuer.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private_key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(stream) = acceptor.accept(stream).await else {
            return;
        };
        let expected_authority = format!("localhost:{}", address.port());
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let expected_authority = expected_authority.clone();
            async move {
                assert_eq!(request.uri().path(), "/through-freja");
                assert_eq!(
                    request.headers().get(http::header::HOST).unwrap(),
                    expected_authority.as_str()
                );
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"h1-ok"))))
            }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    (address, task)
}

pub(super) async fn spawn_tls_h2(
    issuer: &CertifiedIssuer<'_, KeyPair>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let leaf_key = KeyPair::generate().unwrap();
    let parameters = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let leaf = parameters.signed_by(&leaf_key, issuer).unwrap();
    let chain = vec![leaf.der().clone(), issuer.der().clone()];
    let private_key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, private_key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri().path(), "/through-freja");
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"h2-ok"))))
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });
    (address, task)
}

pub(super) fn interception_fixture(
    issuer: &CertifiedIssuer<'_, KeyPair>,
    ca_key_pem: &str,
) -> (TlsInterceptor, std::path::PathBuf) {
    let directory = std::env::temp_dir().join(format!("freja-tls-test-{}", SessionId::new()));
    fs::create_dir(&directory).unwrap();
    let ca_certificate = directory.join("ca.pem");
    let ca_private_key = directory.join("ca-key.pem");
    fs::write(&ca_certificate, issuer.pem()).unwrap();
    fs::write(&ca_private_key, ca_key_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&ca_private_key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let tls_config = TlsInterceptionConfig::new(
        ca_certificate,
        ca_private_key,
        vec![HostPattern::Exact(HostName::new("localhost").unwrap())],
        4,
    )
    .unwrap();
    let mut upstream_roots = RootCertStore::empty();
    upstream_roots.add(issuer.der().clone()).unwrap();
    let interceptor = TlsInterceptor::from_config_and_roots(&tls_config, upstream_roots).unwrap();
    (interceptor, directory)
}

pub(super) async fn open_connect_tunnel(
    proxy: std::net::SocketAddr,
    upstream_port: u16,
) -> TcpStream {
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT localhost:{upstream_port} HTTP/1.1\r\nHost: localhost:{upstream_port}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    client
}

pub(super) async fn spawn_body_origin(
    response_body: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1_024];
        loop {
            let count = timeout(Duration::from_millis(250), stream.read(&mut buffer))
                .await
                .unwrap_or(Ok(0))
                .unwrap_or(0);
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
            if request.windows(7).any(|window| window == b"MALWARE")
                || request.ends_with(b"\r\n\r\n")
            {
                break;
            }
        }
        if !request.is_empty() {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(response_body).await.unwrap();
        }
        request
    });
    (address, task)
}

pub(super) async fn spawn_recording_origin() -> (
    std::net::SocketAddr,
    oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = read_head(&mut stream).await;
        let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let content_length = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let mut body = vec![0_u8; content_length];
        stream.read_exact(&mut body).await.unwrap();
        request.extend_from_slice(&body);
        sender.send(request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    (address, receiver, task)
}

pub(super) fn collect_events(receiver: &mut mpsc::Receiver<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}
