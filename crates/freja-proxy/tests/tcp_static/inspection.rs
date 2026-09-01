use super::*;

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
