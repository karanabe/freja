use super::*;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn repeat_executes_twice_with_fresh_ids_without_pausing_again() {
    let (origin, mut observed, origin_task) = spawn_repeat_origin(2).await;
    let (services, mut audit) = services(Vec::new(), local_access());
    let hooks = HookRunner::new(
        HookMode::Interactive,
        HookRegistry::default(),
        Duration::from_secs(1),
        HookFailurePolicy::FailClosed,
    );
    let (broker, mut intercepts) = InteractiveBroker::channel(
        2,
        1,
        Duration::from_secs(1),
        InterceptTimeoutPolicy::FailClosed,
    )
    .unwrap();
    let services = services
        .with_hooks(hooks)
        .with_interactive_broker(broker)
        .with_ui_capture(UiCaptureSettings::new(4, 4).unwrap());
    let (commands, command_receiver) = mpsc::channel(2);
    let (result_sender, mut results) = mpsc::channel(2);
    let (shutdown, signal) = shutdown_channel();
    let worker = tokio::spawn(
        HttpRepeatExecutor::new(command_receiver, result_sender, services, limits()).run(signal),
    );
    let source = InterceptContext {
        session_id: SessionId::new(),
        transaction_id: freja_domain::TransactionId::new(),
        source_ip: IpAddr::from([127, 0, 0, 1]),
    };
    let request = RepeatRequest {
        source,
        request: HttpRequestSnapshot {
            method: http::Method::POST,
            uri: format!("http://{origin}/repeat").parse().unwrap(),
            version: http::Version::HTTP_11,
            headers: http::HeaderMap::from_iter([
                (
                    http::header::HOST,
                    http::HeaderValue::from_static("ignored.invalid"),
                ),
                (
                    http::header::PROXY_AUTHORIZATION,
                    http::HeaderValue::from_static("Basic should-not-return"),
                ),
                (
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_static("3"),
                ),
            ]),
            body: WireBody::new("one"),
            maximum_head_bytes: 16 * 1_024,
            maximum_body_bytes: 16 * 1_024,
        },
    };

    commands.send(request.clone()).await.unwrap();
    commands.send(request).await.unwrap();
    let first = timeout(Duration::from_secs(2), results.recv())
        .await
        .unwrap()
        .unwrap();
    let second = timeout(Duration::from_secs(2), results.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(first.session_id, second.session_id);
    assert_ne!(first.transaction_id, second.transaction_id);
    for result in [first, second] {
        let RepeatOutcome::Response(response) = result.outcome else {
            panic!("repeat should return a response");
        };
        assert_eq!(response.status, http::StatusCode::OK);
        assert_eq!(response.body, b"hell");
        assert_eq!(response.observed_body_bytes, 5);
        assert!(response.body_truncated);
    }
    for _ in 0..2 {
        let request = String::from_utf8(observed.recv().await.unwrap()).unwrap();
        assert!(request.starts_with("POST /repeat HTTP/1.1\r\n"));
        assert!(request.contains(&format!("host: {origin}\r\n")));
        assert!(!request.contains("proxy-authorization"));
        assert!(request.ends_with("\r\n\r\none"));
    }
    assert!(
        timeout(Duration::from_millis(50), intercepts.recv())
            .await
            .is_err()
    );
    shutdown.shutdown();
    timeout(Duration::from_secs(2), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    origin_task.await.unwrap();

    let events = collect_events(&mut audit);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event, AuditEvent::HttpRepeatStarted { .. }))
            .count(),
        2
    );
    assert!(
        events
            .iter()
            .all(|event| !matches!(event.event, AuditEvent::ManualModification { .. }))
    );
}

#[tokio::test]
async fn https_repeat_uses_interception_allowlist_and_authenticated_http1_tls() {
    let (issuer, key_pem) = test_ca();
    let (origin, origin_task) = spawn_tls_http1(&issuer).await;
    let (interceptor, directory) = interception_fixture(&issuer, &key_pem);
    let (services, _audit) = services(Vec::new(), local_access());
    let services = services
        .with_tls_interceptor(interceptor)
        .with_ui_capture(UiCaptureSettings::new(16, 2).unwrap());
    let (commands, command_receiver) = mpsc::channel(1);
    let (result_sender, mut results) = mpsc::channel(1);
    let (shutdown, signal) = shutdown_channel();
    let worker = tokio::spawn(
        HttpRepeatExecutor::new(command_receiver, result_sender, services, limits()).run(signal),
    );
    commands
        .send(RepeatRequest {
            source: InterceptContext {
                session_id: SessionId::new(),
                transaction_id: freja_domain::TransactionId::new(),
                source_ip: IpAddr::from([127, 0, 0, 1]),
            },
            request: HttpRequestSnapshot {
                method: http::Method::GET,
                uri: format!("https://localhost:{}/through-freja", origin.port())
                    .parse()
                    .unwrap(),
                version: http::Version::HTTP_11,
                headers: http::HeaderMap::new(),
                body: WireBody::new(Bytes::new()),
                maximum_head_bytes: 16 * 1_024,
                maximum_body_bytes: 16 * 1_024,
            },
        })
        .await
        .unwrap();

    let result = timeout(Duration::from_secs(2), results.recv())
        .await
        .unwrap()
        .unwrap();
    let RepeatOutcome::Response(response) = result.outcome else {
        panic!("HTTPS repeat should return a response");
    };
    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.body, b"h1-ok");
    shutdown.shutdown();
    worker.await.unwrap().unwrap();
    origin_task.await.unwrap();
    fs::remove_dir_all(directory).unwrap();
}

async fn spawn_repeat_origin(
    attempts: usize,
) -> (
    std::net::SocketAddr,
    mpsc::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = mpsc::channel(attempts.max(1));
    let task = tokio::spawn(async move {
        for _ in 0..attempts {
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
            sender.send(request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                )
                .await
                .unwrap();
        }
    });
    (address, receiver, task)
}
