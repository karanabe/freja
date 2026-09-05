use freja_domain::EvaluationTarget;

use super::*;

#[tokio::test]
async fn connect_evaluation_targets_match_the_facts_used_by_policy() {
    let (echo, echo_task) = spawn_echo().await;
    let (services, mut audit) = services(Vec::new(), local_access());
    let sink = RecordingEventSink::default();
    let (proxy, shutdown, proxy_task) = bind_proxy(
        vec![Port::new(echo.port()).unwrap()],
        services.with_event_sink(sink.clone()),
    )
    .await;
    let mut client = open_connect_tunnel(proxy, echo.port()).await;
    client.write_all(b"tunnel").await.unwrap();
    let mut response = [0; 6];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"tunnel");
    drop(client);
    echo_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let mut latest_facts = None;
    let mut expected = Vec::new();
    for envelope in collect_events(&mut audit) {
        match envelope.event {
            AuditEvent::ReplayFactsObserved { facts } => {
                latest_facts = match facts {
                    ReplayFacts::Requested(facts) => Some(EvaluationTarget::Requested(facts)),
                    ReplayFacts::Resolved(facts) => Some(EvaluationTarget::Resolved(facts)),
                    ReplayFacts::HttpRequest(facts) => {
                        Some(EvaluationTarget::Resolved(facts.target().clone()))
                    }
                    _ => None,
                };
            }
            AuditEvent::AclEvaluated { decision } => expected.push((
                envelope.context.session_id,
                envelope.context.transaction_id,
                decision.trace,
                latest_facts.clone(),
            )),
            _ => {}
        }
    }
    let observed = sink
        .events()
        .into_iter()
        .filter_map(|event| match event {
            DataPlaneEvent::DecisionMade {
                session_id,
                transaction_id,
                trace,
                target,
            } => Some((session_id, transaction_id, trace, target)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(expected.len() >= 3);
    assert_eq!(observed, expected);
    assert!(
        observed
            .iter()
            .any(|(_, _, _, target)| matches!(target, Some(EvaluationTarget::Requested(_))))
    );
    assert!(observed.iter().any(|(_, _, _, target)| matches!(target, Some(EvaluationTarget::Resolved(facts)) if facts.resolved_ip() == echo.ip())));
    assert!(observed.iter().all(|(_, _, _, target)| match target {
        Some(EvaluationTarget::Requested(facts)) =>
            facts.source_ip().is_loopback() && facts.destination_port().get() == echo.port(),
        Some(EvaluationTarget::Resolved(facts)) =>
            facts.requested().source_ip().is_loopback()
                && facts.requested().destination_port().get() == echo.port(),
        None => false,
    }));
}

#[tokio::test]
async fn http_body_inspection_retains_the_selected_connection_target() {
    for (direction, mode) in [
        (Direction::HttpRequestBody, InspectionMode::Preflight),
        (Direction::HttpRequestBody, InspectionMode::Streaming),
        (Direction::HttpResponseBody, InspectionMode::Preflight),
        (Direction::HttpResponseBody, InspectionMode::Streaming),
    ] {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nMALWARE";
        let (origin, origin_task) = spawn_fixed_origin(response).await;
        let (services, _audit) =
            inspected_services_in_mode(direction, EnforcementMode::Observe, mode);
        let sink = RecordingEventSink::default();
        let (proxy, shutdown, proxy_task) =
            bind_proxy(vec![Port::HTTPS], services.with_event_sink(sink.clone())).await;
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(format!("POST http://{origin}/inspect HTTP/1.1\r\nHost: {origin}\r\nContent-Length: 7\r\n\r\nMALWARE").as_bytes()).await.unwrap();
        assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
        let mut body = [0; 7];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"MALWARE");
        drop(client);
        origin_task.await.unwrap();
        stop_proxy(shutdown, proxy_task).await;
        let events = sink.events();
        let target = events.iter().find_map(|event| match event {
            DataPlaneEvent::DecisionMade { trace, target, .. }
                if trace
                    .matched_rule
                    .as_ref()
                    .is_some_and(|id| id.as_str() == "block-http-body-signature") =>
            {
                target.as_ref()
            }
            _ => None,
        });
        assert!(
            matches!(target, Some(EvaluationTarget::Resolved(facts)) if facts.resolved_ip() == origin.ip() && facts.requested().destination_port().get() == origin.port())
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, DataPlaneEvent::WireCaptured { .. }))
        );
    }
}
