use super::*;

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
        let request = intercepts.recv().await.unwrap();
        let snapshot = &request.request;
        assert_eq!(snapshot.method, http::Method::POST);
        assert_eq!(snapshot.body.bytes().as_ref(), b"old");
        request
            .response
            .send(InteractiveDecision::ReplaceBody(DecodedBody::new(
                "manual-body",
            )))
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), intercepts.recv())
                .await
                .is_err()
        );
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
    assert!(upstream.contains("content-length: 11\r\n"));
    assert!(upstream.ends_with("\r\n\r\nmanual-body"));
    drop(client);
    responder.await.unwrap();
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ManualModification { action } if action == "replace-body"
    )));
}

#[tokio::test]
async fn interactive_request_rejects_an_oversized_body_without_pausing() {
    let (origin, origin_task) = spawn_body_origin(b"ok").await;
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
    let constrained = limits().with_body_prefix_bytes(4).unwrap();
    let (proxy, shutdown, proxy_task) = bind_proxy_with_limits(
        vec![Port::HTTPS],
        services.with_hooks(hooks).with_interactive_broker(broker),
        constrained,
    )
    .await;
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
    assert!(
        tokio::time::timeout(Duration::from_millis(100), intercepts.recv())
            .await
            .is_err()
    );
    drop(client);
    assert!(origin_task.await.unwrap().is_empty());
    stop_proxy(shutdown, proxy_task).await;
}
