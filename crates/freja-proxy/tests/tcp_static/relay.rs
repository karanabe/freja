use super::*;

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
