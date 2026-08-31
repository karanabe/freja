use std::{convert::Infallible, fs, net::IpAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_config::{Limits, TlsConfig};
use freja_domain::{
    Confidence, DetectorId, Direction, EnforcementMode, HookMode, HostName, HttpForwardListener,
    InspectionMode, ListenEndpoint, PolicyGeneration, Port, ProxyAuthentication,
    ProxyCredentialHash, ReplayFacts, RuleId, SessionId, Severity,
};
use freja_policy::{
    AclPolicy, AclRule, DestinationAccess, DestinationGuard, DestinationGuardSettings, HostPattern,
    HttpHeaderMatcher, InspectionPattern, InspectionProgram, MatchExpression, RuleAction,
    hook::{
        BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookFailurePolicy,
        HookFuture, HookRegistry, HookRunner, HttpRequestBodyHook, HttpRequestHead,
        HttpRequestHeadHook, InteractiveBroker, InteractiveDecision, InterceptStage,
        InterceptTimeoutPolicy, WireBody,
    },
};
use freja_proxy::{DataPlaneServices, HttpForwardServer, TlsInterceptor, shutdown_channel};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn limits() -> Limits {
    Limits {
        connections: 8,
        header_bytes: 16 * 1_024,
        body_prefix_bytes: 16 * 1_024,
        connect_timeout: Duration::from_secs(1),
        read_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(2),
        paused_flows: 2,
        interception_timeout: Duration::from_secs(1),
        ui_event_capacity: 8,
    }
}

fn inspected_services(
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

fn services(
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

fn local_access() -> DestinationGuardSettings {
    DestinationGuardSettings {
        loopback: DestinationAccess::Allow,
        ..DestinationGuardSettings::default()
    }
}

async fn bind_proxy(
    connect_ports: Vec<Port>,
    services: DataPlaneServices,
) -> (
    std::net::SocketAddr,
    freja_proxy::ShutdownSender,
    tokio::task::JoinHandle<Result<(), freja_proxy::ProxyError>>,
) {
    bind_proxy_with_limits(connect_ports, services, limits()).await
}

async fn bind_proxy_with_limits(
    connect_ports: Vec<Port>,
    services: DataPlaneServices,
    limits: Limits,
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

async fn bind_proxy_with_authentication(
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

async fn stop_proxy(
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

#[tokio::test]
async fn configured_read_timeout_closes_a_partial_request_head() {
    let (services, _audit) = services(Vec::new(), local_access());
    let mut short_limits = limits();
    short_limits.read_timeout = Duration::from_millis(25);
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_limits(vec![Port::HTTPS], services, short_limits).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test")
        .await
        .unwrap();

    let mut response = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();

    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn preflight_request_body_read_timeout_returns_request_timeout() {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut discarded = Vec::new();
        stream.read_to_end(&mut discarded).await.unwrap();
        discarded
    });
    let (services, _audit) = services(Vec::new(), local_access());
    let inspection = InspectionProgram::empty(PolicyGeneration::new(31).unwrap());
    let services = services.with_inspection(inspection, InspectionMode::Preflight);
    let mut short_limits = limits();
    short_limits.read_timeout = Duration::from_millis(25);
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_limits(vec![Port::HTTPS], services, short_limits).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://localhost:{}/upload HTTP/1.1\r\nHost: ignored.test\r\nContent-Length: 8\r\n\r\nabc",
                upstream.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 408"));

    stop_proxy(shutdown, proxy_task).await;
    assert!(upstream_task.await.unwrap().is_empty());
}

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() < 64 * 1_024);
    }
    bytes
}

async fn spawn_origin() -> (
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

async fn spawn_fixed_origin(
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

async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
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

fn test_ca() -> (CertifiedIssuer<'static, KeyPair>, String) {
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

async fn spawn_tls_http1(
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

async fn spawn_tls_h2(
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

fn interception_fixture(
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
    let tls_config = TlsConfig::Intercept {
        ca_certificate,
        ca_private_key,
        intercept_hosts: vec![HostPattern::Exact(HostName::new("localhost").unwrap())],
        leaf_cache_entries: 4,
    };
    let mut upstream_roots = RootCertStore::empty();
    upstream_roots.add(issuer.der().clone()).unwrap();
    let interceptor = TlsInterceptor::from_config_and_roots(&tls_config, upstream_roots)
        .unwrap()
        .unwrap();
    (interceptor, directory)
}

async fn open_connect_tunnel(proxy: std::net::SocketAddr, upstream_port: u16) -> TcpStream {
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

async fn spawn_body_origin(
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

async fn spawn_recording_origin() -> (
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

fn collect_events(receiver: &mut mpsc::Receiver<AuditEnvelope>) -> Vec<AuditEnvelope> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}

#[tokio::test]
async fn absolute_form_is_forwarded_as_origin_form_with_regenerated_host() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let deny_spoofed_host = AclRule {
        id: RuleId::new("deny-spoofed-host-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "host".to_owned(),
            value_contains: Some("attacker.invalid".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_spoofed_host], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/path?q=1 HTTP/1.1\r\nHost: attacker.invalid\r\nProxy-Authorization: Basic secret\r\nConnection: x-remove\r\nX-Remove: yes\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut body = [0_u8; 5];
    client.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&body, b"hello");
    drop(client);
    let upstream_request = observed_request.await.unwrap();
    origin_task.await.unwrap();
    assert!(upstream_request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    assert!(upstream_request.contains(&format!("host: {origin}\r\n")));
    assert!(
        !upstream_request
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    assert!(!upstream_request.to_ascii_lowercase().contains("x-remove:"));
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::HttpRequestObserved { .. }))
    );
    assert!(events.iter().any(|event| matches!(
        event.event,
        AuditEvent::HttpResponseObserved { status: 200, .. }
    )));
}

#[tokio::test]
async fn head_response_preserves_representation_content_length_without_a_body() {
    let (origin, origin_task) =
        spawn_fixed_origin(b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\nConnection: close\r\n\r\n")
            .await;
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "HEAD http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await)
        .unwrap()
        .to_ascii_lowercase();
    assert!(response_head.starts_with("http/1.1 200"));
    assert!(response_head.contains("content-length: 123\r\n"));
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert!(body.is_empty());

    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn no_content_response_does_not_gain_a_content_length() {
    let (origin, origin_task) =
        spawn_fixed_origin(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await;
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await)
        .unwrap()
        .to_ascii_lowercase();
    assert!(response_head.starts_with("http/1.1 204"));
    assert!(!response_head.contains("content-length:"));
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert!(body.is_empty());

    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn connect_establishes_upstream_before_tunneling() {
    let (echo, echo_task) = spawn_echo().await;
    let (services, mut audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) =
        bind_proxy(vec![Port::new(echo.port()).unwrap()], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    client.write_all(b"tunnel").await.unwrap();
    let mut response = [0_u8; 6];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"tunnel");
    drop(client);
    echo_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        event.event,
        AuditEvent::TunnelClosed {
            client_to_upstream_bytes: 6,
            upstream_to_client_bytes: 6,
            ..
        }
    )));
}

#[tokio::test]
async fn opted_in_connect_interception_runs_the_http1_pipeline() {
    let (issuer, ca_key_pem) = test_ca();
    let (upstream, upstream_task) = spawn_tls_http1(&issuer).await;
    let (interceptor, directory) = interception_fixture(&issuer, &ca_key_pem);
    let (base_services, mut audit) = services(Vec::new(), local_access());
    let services = base_services.with_tls_interceptor(interceptor);
    let (proxy, shutdown, proxy_task) =
        bind_proxy(vec![Port::new(upstream.port()).unwrap()], services).await;

    let client = open_connect_tunnel(proxy, upstream.port()).await;

    let mut downstream_roots = RootCertStore::empty();
    downstream_roots.add(issuer.der().clone()).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(downstream_roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from("localhost".to_owned()).unwrap(),
            client,
        )
        .await
        .unwrap();
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .uri("/through-freja")
        .header(http::header::HOST, "spoofed.invalid")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "h1-ok");
    drop(sender);
    connection_task.await.unwrap().unwrap();
    upstream_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
    fs::remove_dir_all(directory).unwrap();

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::TlsCertificateGenerated {
            hostname,
            cache_hit: false,
        } if hostname == "localhost"
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::TlsInterceptionEstablished {
            hostname,
            alpn: Some(alpn),
        } if hostname == "localhost" && alpn == "http/1.1"
    )));
}

#[tokio::test]
async fn intercepted_connect_relays_an_http2_exchange() {
    let (issuer, ca_key_pem) = test_ca();
    let (upstream, upstream_task) = spawn_tls_h2(&issuer).await;
    let (interceptor, directory) = interception_fixture(&issuer, &ca_key_pem);
    let (base_services, mut audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(
        vec![Port::new(upstream.port()).unwrap()],
        base_services.with_tls_interceptor(interceptor),
    )
    .await;
    let client = open_connect_tunnel(proxy, upstream.port()).await;

    let mut downstream_roots = RootCertStore::empty();
    downstream_roots.add(issuer.der().clone()).unwrap();
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(downstream_roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    let tls = TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from("localhost".to_owned()).unwrap(),
            client,
        )
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .uri("https://localhost/through-freja")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "h2-ok");
    drop(sender);
    connection_task.await.unwrap().unwrap();
    upstream_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
    fs::remove_dir_all(directory).unwrap();

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ReplayFactsObserved {
            facts: ReplayFacts::HttpRequest(facts),
        } if facts.path() == "/through-freja"
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HttpResponseObserved { status: 200, .. }
            if event.context.transaction_id.is_some()
    )));
}

#[tokio::test]
async fn certificate_pinning_failure_closes_and_audits_the_intercepted_tunnel() {
    let (issuer, ca_key_pem) = test_ca();
    let (upstream, upstream_task) = spawn_tls_http1(&issuer).await;
    let (interceptor, directory) = interception_fixture(&issuer, &ca_key_pem);
    let (base_services, mut audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(
        vec![Port::new(upstream.port()).unwrap()],
        base_services.with_tls_interceptor(interceptor),
    )
    .await;
    let client = open_connect_tunnel(proxy, upstream.port()).await;

    let client_config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let result = TlsConnector::from(Arc::new(client_config))
        .connect(
            ServerName::try_from("localhost".to_owned()).unwrap(),
            client,
        )
        .await;
    assert!(result.is_err());

    upstream_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
    fs::remove_dir_all(directory).unwrap();
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::TunnelClosed { outcome, .. } if outcome == "tls-client-rejected"
    )));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::TlsInterceptionEstablished { .. }))
    );
}

#[tokio::test]
async fn connect_port_outside_listener_allowlist_is_forbidden() {
    let (services, mut audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("connect-port-allowlist")
    )));
}

#[tokio::test]
async fn proxy_authentication_rejects_missing_credentials_and_strips_valid_credentials() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let credential = Sha256::digest(b"user:password");
    let mut credential_hash = [0_u8; 32];
    credential_hash.copy_from_slice(&credential);
    let authentication =
        ProxyAuthentication::new("Freja", ProxyCredentialHash::new(credential_hash)).unwrap();
    let (services, mut audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_authentication(authentication, services).await;

    let mut unauthenticated = TcpStream::connect(proxy).await.unwrap();
    unauthenticated
        .write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut unauthenticated).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 407"));
    assert!(response_head.contains("proxy-authenticate: Basic realm=\"Freja\""));
    drop(unauthenticated);

    let mut authenticated = TcpStream::connect(proxy).await.unwrap();
    authenticated
        .write_all(
            format!(
                "GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nProxy-Authorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut authenticated).await).unwrap();
    let mut body = [0_u8; 5];
    authenticated.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&body, b"hello");
    drop(authenticated);
    let upstream_request = observed_request.await.unwrap();
    origin_task.await.unwrap();
    assert!(
        !upstream_request
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ProxyAuthentication { outcome } if outcome == "rejected"
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ProxyAuthentication { outcome } if outcome == "accepted"
    )));
}

#[tokio::test]
async fn denied_http_destination_returns_synthetic_forbidden() {
    let deny_host = AclRule {
        id: RuleId::new("deny-blocked-host").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("blocked.test").unwrap(),
        )),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_host], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://blocked.test/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-blocked-host")
    )));
}

#[tokio::test]
async fn request_header_policy_denial_happens_before_upstream_connect() {
    let deny_header = AclRule {
        id: RuleId::new("deny-request-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "x-freja-block".to_owned(),
            value_contains: Some("yes".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_header], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: ignored.invalid\r\nX-Freja-Block: yes\r\n\r\n",
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-request-header")
    )));
}

#[tokio::test]
async fn response_header_policy_denial_replaces_the_upstream_response() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let deny_header = AclRule {
        id: RuleId::new("deny-response-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "x-upstream".to_owned(),
            value_contains: Some("yes".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_header], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    observed_request.await.unwrap();
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-response-header")
                && decision.trace.evaluated_stage == freja_domain::PolicyStage::HttpResponse
    )));
}

#[tokio::test]
async fn hostname_allowed_by_acl_is_forbidden_after_loopback_resolution() {
    let allow_hostname = AclRule {
        id: RuleId::new("allow-localhost").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("localhost").unwrap(),
        )),
        action: RuleAction::Allow,
    };
    let (services, mut audit) = services(vec![allow_hostname], DestinationGuardSettings::default());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://localhost:9/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("protect-loopback-destination")
    )));
}

#[tokio::test]
async fn preflight_request_body_detection_returns_block_page_before_forwarding() {
    let (origin, origin_task) = spawn_body_origin(b"ok").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpRequestBody, EnforcementMode::Enforce);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/upload HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: 7\r\n\r\nMALWARE"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    let upstream_bytes = origin_task.await.unwrap();
    assert!(upstream_bytes.is_empty());
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FindingDetected { finding }
            if finding.direction == Direction::HttpRequestBody
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HttpResponseObserved { status: 403, .. }
    )));
}

#[tokio::test]
async fn preflight_response_body_detection_replaces_upstream_response() {
    let (origin, origin_task) = spawn_body_origin(b"MALWARE").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpResponseBody, EnforcementMode::Enforce);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/download HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    assert!(!origin_task.await.unwrap().is_empty());
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FindingDetected { finding }
            if finding.direction == Direction::HttpResponseBody
    )));
}

#[tokio::test]
async fn observe_mode_records_response_body_finding_without_replacement() {
    let (origin, origin_task) = spawn_body_origin(b"MALWARE").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpResponseBody, EnforcementMode::Observe);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/download HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut body = [0_u8; 7];
    client.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&body, b"MALWARE");
    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::InspectionEvaluated { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::ActionExecuted { .. }))
    );
}

#[tokio::test]
async fn unavailable_upstream_returns_bad_gateway() {
    let unavailable = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{unavailable}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 502"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn configured_header_budget_rejects_oversized_requests() {
    let (services, _audit) = services(Vec::new(), local_access());
    let mut constrained = limits();
    constrained.header_bytes = 64;
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_limits(vec![Port::HTTPS], services, constrained).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: ignored.invalid\r\nX-Large: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n",
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 400"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn preflight_body_budget_rejects_without_forwarding_body() {
    let (origin, origin_task) = spawn_body_origin(b"ok").await;
    let generation = PolicyGeneration::new(36).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit, _receiver) = AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    let services = DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit)
        .with_inspection(
            InspectionProgram::empty(generation),
            InspectionMode::Preflight,
        );
    let mut constrained = limits();
    constrained.body_prefix_bytes = 4;
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_limits(vec![Port::HTTPS], services, constrained).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: 5\r\n\r\n12345"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 413"));
    drop(client);
    assert!(origin_task.await.unwrap().is_empty());
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn slow_upstream_response_returns_gateway_timeout() {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_head(&mut stream).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    });
    let (services, _audit) = services(Vec::new(), local_access());
    let mut short_limits = limits();
    short_limits.idle_timeout = Duration::from_millis(50);
    let (proxy, shutdown, proxy_task) =
        bind_proxy_with_limits(vec![Port::HTTPS], services, short_limits).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{upstream}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 504"));
    drop(client);
    upstream_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn downstream_connection_supports_sequential_keep_alive_requests() {
    let (first_origin, first_request, first_task) = spawn_origin().await;
    let (second_origin, second_request, second_task) = spawn_origin().await;
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();

    for origin in [first_origin, second_origin] {
        client
            .write_all(
                format!("GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
        let mut body = [0_u8; 5];
        client.read_exact(&mut body).await.unwrap();
        assert!(response_head.starts_with("HTTP/1.1 200"));
        assert_eq!(&body, b"hello");
    }
    drop(client);
    first_request.await.unwrap();
    second_request.await.unwrap();
    first_task.await.unwrap();
    second_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn atomic_reload_changes_policy_generation_for_existing_listener() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let generation = PolicyGeneration::new(34).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit_publisher, mut audit) =
        AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    let services = DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit_publisher);
    let reload_handle = services.clone();
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;

    let mut allowed = TcpStream::connect(proxy).await.unwrap();
    allowed
        .write_all(
            format!(
                "GET http://localhost:{}/before HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n",
                origin.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut allowed).await).unwrap();
    let mut body = [0_u8; 5];
    allowed.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    drop(allowed);
    observed_request.await.unwrap();
    origin_task.await.unwrap();

    let reloaded_generation = PolicyGeneration::new(35).unwrap();
    let deny_localhost = AclRule {
        id: RuleId::new("deny-localhost-after-reload").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("localhost").unwrap(),
        )),
        action: RuleAction::Deny,
    };
    reload_handle.reload(
        AclPolicy::new(reloaded_generation, vec![deny_localhost], RuleAction::Allow).unwrap(),
        DestinationGuard::new(local_access()).unwrap(),
        EnforcementMode::Enforce,
        InspectionProgram::empty(reloaded_generation),
        InspectionMode::Streaming,
    );

    let mut denied = TcpStream::connect(proxy).await.unwrap();
    denied
        .write_all(
            format!(
                "GET http://localhost:{}/after HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n",
                origin.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response_head = String::from_utf8(read_head(&mut denied).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(denied);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.policy_generation == reloaded_generation
                && decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                    == Some("deny-localhost-after-reload")
    )));
}

struct AddRequestHeader;

impl HttpRequestHeadHook for AddRequestHeader {
    fn call<'a>(&'a self, _input: &'a HttpRequestHead) -> HookFuture<'a, HeadMutationPlan> {
        Box::pin(async {
            Ok(HeadMutationPlan {
                headers: vec![HeaderMutation::Set {
                    name: "x-freja-hook".parse().unwrap(),
                    value: "applied".parse().unwrap(),
                }],
            })
        })
    }
}

struct ReplaceRequestBody;

impl HttpRequestBodyHook for ReplaceRequestBody {
    fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
        Box::pin(async { Ok(BodyMutationPlan::Replace(DecodedBody::new("longer-body"))) })
    }
}

#[tokio::test]
async fn automatic_http_hooks_mutate_headers_body_and_reconstruct_framing() {
    let (origin, observed, origin_task) = spawn_recording_origin().await;
    let generation = PolicyGeneration::new(32).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit_publisher, mut audit) =
        AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    let mut registry = HookRegistry::default();
    registry.register_request_head(Arc::new(AddRequestHeader));
    registry.register_request_body(Arc::new(ReplaceRequestBody));
    let hooks = HookRunner::new(
        HookMode::Automatic,
        registry,
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let services = DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit_publisher)
        .with_inspection(
            InspectionProgram::empty(generation),
            InspectionMode::Preflight,
        )
        .with_hooks(hooks);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/hook HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nold"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut response_body = [0_u8; 2];
    client.read_exact(&mut response_body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&response_body, b"ok");
    let upstream = String::from_utf8(observed.await.unwrap()).unwrap();
    assert!(upstream.contains("x-freja-hook: applied\r\n"));
    assert!(upstream.contains("content-length: 11\r\n"));
    assert!(!upstream.contains("content-encoding"));
    assert!(upstream.ends_with("\r\n\r\nlonger-body"));
    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HookExecuted { stage, outcome }
            if stage == "http-request-head" && outcome == "completed"
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HookExecuted { stage, outcome }
            if stage == "http-request-body" && outcome == "completed"
    )));
}

#[tokio::test]
async fn streaming_body_hooks_reject_content_encoded_requests_before_forwarding() {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let origin = listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        received
    });
    let generation = PolicyGeneration::new(37).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit_publisher, _audit) =
        AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    let mut registry = HookRegistry::default();
    registry.register_request_body(Arc::new(ReplaceRequestBody));
    let hooks = HookRunner::new(
        HookMode::Automatic,
        registry,
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let services = DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit_publisher)
        .with_inspection(
            InspectionProgram::empty(generation),
            InspectionMode::Streaming,
        )
        .with_hooks(hooks);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/encoded HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nold"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 422"));

    stop_proxy(shutdown, proxy_task).await;
    assert!(origin_task.await.unwrap().is_empty());
}

#[tokio::test]
async fn interactive_http_actions_mutate_bounded_request_and_are_audited() {
    let (origin, observed, origin_task) = spawn_recording_origin().await;
    let generation = PolicyGeneration::new(33).unwrap();
    let policy = AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap();
    let guard = DestinationGuard::new(local_access()).unwrap();
    let (audit_publisher, mut audit) =
        AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
    let hooks = HookRunner::new(
        HookMode::Interactive,
        HookRegistry::default(),
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let (broker, mut intercepts) = InteractiveBroker::channel(
        8,
        2,
        Duration::from_secs(1),
        InterceptTimeoutPolicy::FailClosed,
    )
    .unwrap();
    let services = DataPlaneServices::new(policy, guard, EnforcementMode::Enforce, audit_publisher)
        .with_inspection(
            InspectionProgram::empty(generation),
            InspectionMode::Preflight,
        )
        .with_hooks(hooks)
        .with_interactive_broker(broker);
    let responder = tokio::spawn(async move {
        let request_head = intercepts.recv().await.unwrap();
        assert_eq!(request_head.stage, InterceptStage::HttpRequestHead);
        request_head
            .response
            .send(InteractiveDecision::EditHeaders(HeadMutationPlan {
                headers: vec![HeaderMutation::Set {
                    name: "x-freja-manual".parse().unwrap(),
                    value: "approved".parse().unwrap(),
                }],
            }))
            .unwrap();

        let request_body = intercepts.recv().await.unwrap();
        assert_eq!(request_body.stage, InterceptStage::HttpRequestBody);
        request_body
            .response
            .send(InteractiveDecision::ReplaceBody(DecodedBody::new(
                "manual-body",
            )))
            .unwrap();

        let response_head = intercepts.recv().await.unwrap();
        assert_eq!(response_head.stage, InterceptStage::HttpResponseHead);
        response_head
            .response
            .send(InteractiveDecision::Continue)
            .unwrap();

        let response_body = intercepts.recv().await.unwrap();
        assert_eq!(response_body.stage, InterceptStage::HttpResponseBody);
        response_body
            .response
            .send(InteractiveDecision::Continue)
            .unwrap();
    });
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/manual HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: 3\r\n\r\nold"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut response_body = [0_u8; 2];
    client.read_exact(&mut response_body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&response_body, b"ok");
    let upstream = String::from_utf8(observed.await.unwrap()).unwrap();
    assert!(upstream.contains("x-freja-manual: approved\r\n"));
    assert!(upstream.contains("content-length: 11\r\n"));
    assert!(upstream.ends_with("\r\n\r\nmanual-body"));
    drop(client);
    responder.await.unwrap();
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ManualModification { action } if action == "edit-headers"
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ManualModification { action } if action == "replace-body"
    )));
}
