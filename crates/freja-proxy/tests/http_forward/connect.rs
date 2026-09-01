use super::*;

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
async fn interactive_connect_pauses_once_before_tunnel_commitment() {
    let (echo, echo_task) = spawn_echo().await;
    let (services, _audit) = services(Vec::new(), local_access());
    let hooks = HookRunner::new(
        HookMode::Interactive,
        HookRegistry::default(),
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let (broker, mut intercepts) = InteractiveBroker::channel(
        4,
        2,
        Duration::from_secs(1),
        InterceptTimeoutPolicy::FailClosed,
    )
    .unwrap();
    let responder = tokio::spawn(async move {
        let request = intercepts.recv().await.unwrap();
        assert_eq!(request.request.method, http::Method::CONNECT);
        assert!(request.request.body.bytes().is_empty());
        request
            .response
            .send(InteractiveDecision::Continue)
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), intercepts.recv())
                .await
                .is_err()
        );
    });
    let (proxy, shutdown, proxy_task) = bind_proxy(
        vec![Port::new(echo.port()).unwrap()],
        services.with_hooks(hooks).with_interactive_broker(broker),
    )
    .await;
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
    responder.await.unwrap();
    echo_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
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
