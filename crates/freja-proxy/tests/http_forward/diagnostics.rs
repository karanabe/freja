use freja_domain::{EvaluationTarget, PolicyStage};

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
                ..
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

#[tokio::test]
async fn acl_definitions_are_paired_with_generation_and_transaction_across_reload() {
    use freja_policy::evidence::RuleSource;
    let (origin, request, origin_task) = spawn_origin().await;
    let rule = AclRule {
        id: RuleId::new("same-id").unwrap(),
        matcher: MatchExpression::All(vec![
            MatchExpression::HttpMethod(["GET".to_owned()].into()),
            MatchExpression::Any(vec![
                MatchExpression::HttpPathPrefix("/same".to_owned()),
                MatchExpression::HttpPathPrefix("/not-matched".to_owned()),
            ]),
        ]),
        action: RuleAction::Allow,
    };
    let (services, mut audit) = services(vec![rule.clone()], local_access());
    let reload = services.clone();
    let sink = RecordingEventSink::default();
    let (proxy, shutdown, task) =
        bind_proxy(vec![Port::HTTPS], services.with_event_sink(sink.clone())).await;
    let wire = format!("GET http://{origin}/same HTTP/1.1\r\nHost: {origin}\r\n\r\n");
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(wire.as_bytes()).await.unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
    let mut body = [0; 5];
    client.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"hello");
    request.await.unwrap();
    origin_task.await.unwrap();
    let old = captured_acl(&sink, 31, PolicyStage::HttpRequest);
    assert_eq!(old.2.source(), RuleSource::Acl);
    assert_eq!(old.1.matched_rule.as_ref(), Some(&rule.id));
    assert!(old.2.conditions().text().contains("/not-matched"));
    assert_eq!(old.2.action().text(), "\"allow\"");
    let old_fallback = captured_acl(&sink, 31, PolicyStage::ResolvedDestination).2;
    let old_acl = old_fallback.acl().unwrap();
    assert_eq!(old_acl.rule_count(), 1);
    assert_eq!(old_acl.evaluated(), 1);
    assert_eq!(old_acl.unavailable(), 1);
    assert!(old_acl.declarations().text().contains("/not-matched"));
    let generation = PolicyGeneration::new(32).unwrap();
    let replacement = AclRule {
        id: rule.id.clone(),
        matcher: MatchExpression::HttpPathPrefix("/same".to_owned()),
        action: RuleAction::Deny,
    };
    reload.reload(
        AclPolicy::new(
            generation,
            vec![
                replacement,
                AclRule {
                    id: RuleId::new("new-unmatched").unwrap(),
                    matcher: MatchExpression::HttpPathPrefix("/new-unmatched".to_owned()),
                    action: RuleAction::Deny,
                },
            ],
            RuleAction::Allow,
        )
        .unwrap(),
        DestinationGuard::new(local_access()).unwrap(),
        EnforcementMode::Enforce,
        InspectionProgram::empty(generation),
        InspectionMode::Streaming,
    );
    client.write_all(wire.as_bytes()).await.unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, task).await;
    let new = captured_acl(&sink, 32, PolicyStage::HttpRequest);
    assert_ne!(old.0, new.0);
    assert_eq!(new.1.matched_rule.as_ref(), Some(&rule.id));
    assert_eq!(old.1.policy_generation.get(), 31);
    assert_eq!(new.2.action().text(), "\"deny\"");
    assert!(!new.2.conditions().text().contains("/not-matched"));
    assert!(old.2.conditions().text().contains("/not-matched"));
    assert_eq!(new.2.acl().unwrap().rule_count(), 2);
    assert!(
        new.2
            .acl()
            .unwrap()
            .declarations()
            .text()
            .contains("not-evaluated-after-first-match")
    );
    let new_fallback = captured_acl(&sink, 32, PolicyStage::ResolvedDestination).2;
    let acl = new_fallback.acl().unwrap();
    assert_eq!(
        (acl.rule_count(), acl.evaluated(), acl.unavailable()),
        (2, 2, 2)
    );
    assert!(acl.declarations().text().contains("/new-unmatched"));
    assert!(!old_acl.declarations().text().contains("/new-unmatched"));
    for envelope in collect_events(&mut audit) {
        // The unmatched condition is sensitive definition content, absent from audit.
        let serialized = serde_json::to_string(&envelope.event).unwrap();
        for definition in ["/not-matched", "/new-unmatched"] {
            assert!(!serialized.contains(definition));
        }
    }
}

#[tokio::test]
async fn active_scanner_keeps_original_definition_and_enforcement_after_reload() {
    use freja_policy::evidence::RuleSource;
    let (first_echo, first_task) = spawn_echo().await;
    let (second_echo, second_task) = spawn_echo().await;
    let (services, _audit) = inspected_services_in_mode(
        Direction::ClientToUpstream,
        EnforcementMode::Observe,
        InspectionMode::Streaming,
    );
    let reload = services.clone();
    let sink = RecordingEventSink::default();
    let (proxy, shutdown, task) = bind_proxy(
        vec![
            Port::new(first_echo.port()).unwrap(),
            Port::new(second_echo.port()).unwrap(),
        ],
        services.with_event_sink(sink.clone()),
    )
    .await;
    let mut old = open_connect_tunnel(proxy, first_echo.port()).await;
    old.write_all(b"MA").await.unwrap();
    let mut prefix = [0; 2];
    old.read_exact(&mut prefix).await.unwrap();
    assert_eq!(&prefix, b"MA");
    let generation = PolicyGeneration::new(32).unwrap();
    let program = InspectionProgram::new(
        generation,
        vec![
            InspectionPattern::new(
                DetectorId::new("http-body-signature").unwrap(),
                RuleId::new("block-http-body-signature").unwrap(),
                b"WARE".to_vec(),
                Severity::Low,
                Confidence::Confirmed,
                vec![Direction::ClientToUpstream],
                RuleAction::Allow,
                vec!["new-definition".to_owned()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    reload.reload(
        AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap(),
        DestinationGuard::new(local_access()).unwrap(),
        EnforcementMode::Enforce,
        program,
        InspectionMode::Streaming,
    );
    old.write_all(b"LWARE").await.unwrap();
    let mut suffix = [0; 5];
    old.read_exact(&mut suffix).await.unwrap();
    assert_eq!(&suffix, b"LWARE"); // Original Observe deny did not block.
    let mut new = open_connect_tunnel(proxy, second_echo.port()).await;
    new.write_all(b"WARE").await.unwrap();
    let mut response = [0; 4];
    new.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"WARE");
    drop(old);
    drop(new);
    first_task.await.unwrap();
    second_task.await.unwrap();
    stop_proxy(shutdown, task).await;
    let decisions = sink
        .events()
        .into_iter()
        .filter_map(|event| match event {
            DataPlaneEvent::DecisionMade {
                trace,
                evidence: Some(evidence),
                ..
            } if evidence.source() == RuleSource::Inspection => Some((trace, evidence)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].0.policy_generation.get(), 31);
    assert_eq!(decisions[0].1.enforcement(), EnforcementMode::Observe);
    assert_eq!(decisions[0].1.action().text(), "\"deny\"");
    assert!(
        !decisions[0]
            .1
            .conditions()
            .text()
            .contains("new-definition")
    );
    assert_eq!(decisions[1].0.policy_generation, generation);
    assert_eq!(decisions[1].1.enforcement(), EnforcementMode::Enforce);
    assert!(
        decisions[1]
            .1
            .conditions()
            .text()
            .contains("new-definition")
    );
}

#[tokio::test]
async fn built_in_provenance_cannot_be_confused_with_a_same_id_acl() {
    use freja_policy::evidence::RuleSource;
    let rule = AclRule {
        id: RuleId::new("protect-loopback-destination").unwrap(),
        matcher: MatchExpression::Protocol(freja_domain::Protocol::Http),
        action: RuleAction::Allow,
    };
    let (services, _audit) = services(vec![rule], DestinationGuardSettings::default());
    let sink = RecordingEventSink::default();
    let (proxy, shutdown, task) =
        bind_proxy(vec![Port::HTTPS], services.with_event_sink(sink.clone())).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://127.0.0.1:12345/ HTTP/1.1\r\nHost: ignored\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 403"));
    drop(client);
    let mut connect = TcpStream::connect(proxy).await.unwrap();
    connect
        .write_all(b"CONNECT 127.0.0.1:12345 HTTP/1.1\r\nHost: ignored\r\n\r\n")
        .await
        .unwrap();
    assert!(read_head(&mut connect).await.starts_with(b"HTTP/1.1 403"));
    drop(connect);
    stop_proxy(shutdown, task).await;
    let evidence = sink
        .events()
        .into_iter()
        .filter_map(|event| match event {
            DataPlaneEvent::DecisionMade { evidence, .. } => evidence,
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        evidence
            .iter()
            .any(|e| e.source() == RuleSource::Acl && e.action().text() == "\"allow\"")
    );
    assert!(
        evidence
            .iter()
            .any(|e| e.source() == RuleSource::DestinationGuard
                && e.conditions().text().contains("127.0.0.0/8")
                && e.action().text() == "\"deny\"")
    );
    assert!(
        evidence
            .iter()
            .any(|e| e.source() == RuleSource::ConnectPorts
                && e.conditions().text().contains("443")
                && e.action().text() == "\"deny\"")
    );
}

#[tokio::test]
async fn unread_bounded_ui_queue_does_not_delay_forwarding() {
    #[derive(Debug, Clone)]
    struct SaturatedSink {
        sender: mpsc::Sender<DataPlaneEvent>,
        dropped: Arc<std::sync::atomic::AtomicU64>,
    }
    impl DataPlaneEventSink for SaturatedSink {
        fn try_publish(&self, event: DataPlaneEvent) {
            if self.sender.try_send(event).is_err() {
                self.dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        fn dropped_events(&self) -> u64 {
            self.dropped.load(std::sync::atomic::Ordering::Relaxed)
        }
    }
    let (sender, _unread) = mpsc::channel(1);
    let sink = SaturatedSink {
        sender,
        dropped: Arc::default(),
    };
    let (services, _audit) = services(Vec::new(), local_access());
    let (origin, request, origin_task) = spawn_origin().await;
    let (proxy, shutdown, task) =
        bind_proxy(vec![Port::HTTPS], services.with_event_sink(sink.clone())).await;
    timeout(Duration::from_secs(2), async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client
            .write_all(
                format!("GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        assert!(read_head(&mut client).await.starts_with(b"HTTP/1.1 200"));
        let mut response = [0; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"hello");
    })
    .await
    .unwrap();
    request.await.unwrap();
    origin_task.await.unwrap();
    stop_proxy(shutdown, task).await;
    assert!(sink.dropped_events() > 0);
}

fn captured_acl(
    sink: &RecordingEventSink,
    generation: u64,
    stage: PolicyStage,
) -> (
    Option<freja_domain::TransactionId>,
    freja_domain::DecisionTrace,
    std::sync::Arc<freja_policy::evidence::RuleEvidence>,
) {
    sink.events()
        .into_iter()
        .find_map(|event| match event {
            DataPlaneEvent::DecisionMade {
                transaction_id,
                trace,
                evidence: Some(evidence),
                ..
            } if trace.policy_generation.get() == generation
                && trace.evaluated_stage == stage
                && evidence.acl().is_some() =>
            {
                Some((transaction_id, trace, evidence))
            }
            _ => None,
        })
        .unwrap()
}
