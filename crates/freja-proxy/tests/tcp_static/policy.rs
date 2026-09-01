use super::*;

#[tokio::test]
async fn requested_destination_denial_closes_before_upstream_connect() {
    let denied_port = Port::new(9).unwrap();
    let rule = AclRule {
        id: RuleId::new("deny-test-port").unwrap(),
        matcher: MatchExpression::DestinationPort(
            PortRange::new(denied_port, denied_port).unwrap(),
        ),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![rule], local_access(), 12);
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Ip(IpAddr::from([127, 0, 0, 1])), 9),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str) == Some("deny-test-port")
    )));
}

#[tokio::test]
async fn tcp_detour_reselects_and_reauthorizes_the_upstream_before_relay() {
    let original = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .unwrap();
    let original_address = original.local_addr().unwrap();
    let (detour, echo_task) = spawn_echo_server().await;
    let detour_rule = AclRule {
        id: RuleId::new("detour-test-port").unwrap(),
        matcher: MatchExpression::All(vec![
            MatchExpression::Protocol(Protocol::Tcp),
            MatchExpression::DestinationPort(
                PortRange::new(
                    Port::new(original_address.port()).unwrap(),
                    Port::new(original_address.port()).unwrap(),
                )
                .unwrap(),
            ),
        ]),
        action: RuleAction::Detour(UpstreamEndpoint::new(
            TargetHost::Ip(detour.ip()),
            Port::new(detour.port()).unwrap(),
        )),
    };
    let (services, mut audit) = services(vec![detour_rule], local_access(), 15);
    let server = StaticTcpServer::bind(
        tcp_spec(
            TargetHost::Ip(original_address.ip()),
            original_address.port(),
        ),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    client.write_all(b"detour").await.unwrap();
    let mut response = [0_u8; 6];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"detour");
    drop(client);
    echo_task.await.unwrap();
    stop_server(shutdown, server_task).await;
    drop(original);

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if matches!(decision.action, EnforcementAction::TcpDetour(_))
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ReplayFactsObserved {
            facts: freja_domain::ReplayFacts::Requested(facts),
        } if facts.destination_port().get() == detour.port()
    )));
}

#[tokio::test]
async fn allowed_hostname_is_denied_after_it_resolves_to_loopback() {
    let allow_hostname = AclRule {
        id: RuleId::new("allow-localhost-name").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("localhost").unwrap(),
        )),
        action: RuleAction::Allow,
    };
    let (services, mut audit) = services(
        vec![allow_hostname],
        DestinationGuardSettings::default(),
        13,
    );
    let server = StaticTcpServer::bind(
        tcp_spec(TargetHost::Name(HostName::new("localhost").unwrap()), 9),
        services,
        limits(),
    )
    .await
    .unwrap();
    let proxy_address = server.local_address();
    let (shutdown, signal) = shutdown_channel();
    let server_task = tokio::spawn(server.run(signal));

    let mut client = TcpStream::connect(proxy_address).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(1), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    stop_server(shutdown, server_task).await;

    let events = collect_events(&mut audit);
    let resolved_count = events.iter().find_map(|event| match &event.event {
        AuditEvent::TargetResolved {
            resolved_addresses, ..
        } => Some(resolved_addresses.len()),
        _ => None,
    });
    assert!(resolved_count.is_some_and(|count| count >= 1));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("protect-loopback-destination")
    )));
}
