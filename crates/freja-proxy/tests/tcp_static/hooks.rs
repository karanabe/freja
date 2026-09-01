use super::*;

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
