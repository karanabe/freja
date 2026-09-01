use super::*;

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
