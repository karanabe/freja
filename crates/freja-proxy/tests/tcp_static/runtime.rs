use super::*;

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
