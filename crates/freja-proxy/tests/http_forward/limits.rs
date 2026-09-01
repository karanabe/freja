use super::*;

#[tokio::test]
async fn configured_read_timeout_closes_a_partial_request_head() {
    let (services, _audit) = services(Vec::new(), local_access());
    let short_limits = limits()
        .with_read_timeout(Duration::from_millis(25))
        .unwrap();
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
    let short_limits = limits()
        .with_read_timeout(Duration::from_millis(25))
        .unwrap();
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
    let constrained = limits().with_header_bytes(64).unwrap();
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
    let constrained = limits().with_body_prefix_bytes(4).unwrap();
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
    let short_limits = limits()
        .with_idle_timeout(Duration::from_millis(50))
        .unwrap();
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
