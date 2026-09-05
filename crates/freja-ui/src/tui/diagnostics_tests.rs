//! Request/evidence ownership and layout regressions using immutable UI events.

use freja_domain::{
    Confidence, DecisionTrace, DetectorId, Direction, EnforcementActionKind, EvaluationTarget,
    EvidenceHash, Finding, HostName, PolicyGeneration, PolicyStage, Port, Protocol,
    RequestedTargetFacts, ResolvedTargetFacts, SessionId, TargetHost, TransactionId,
};
use ratatui::{Terminal, backend::TestBackend};

use super::{TuiModel, render};
use crate::UiEvent;

#[test]
fn each_evaluation_keeps_its_own_connection_target() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    observe(
        &mut model,
        session,
        transaction,
        "CONNECT",
        "example.test:443",
    );
    let requested = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::Name(HostName::new("example.test").unwrap()),
        Port::HTTPS,
        Protocol::Http,
    );
    let targets = [
        EvaluationTarget::Requested(requested.clone()),
        EvaluationTarget::Resolved(ResolvedTargetFacts::new(
            requested.clone(),
            "192.0.2.1".parse().unwrap(),
        )),
        EvaluationTarget::Resolved(ResolvedTargetFacts::new(
            requested,
            "2001:db8::1".parse().unwrap(),
        )),
    ];
    for (index, target) in targets.into_iter().enumerate() {
        let mut event = decision_event(session, Some(transaction), index as u64 + 1);
        if let UiEvent::DecisionMade { target: value, .. } = &mut event {
            *value = Some(target);
        }
        model.apply(event);
        model.show_diagnostics();
        let rendered = screen(&model, 180, 30);
        assert!(rendered.contains("127.0.0.1 -> example.test:443"));
        if index == 0 {
            assert!(rendered.contains("evaluated=unresolved"));
        }
    }
    let rendered = screen(&model, 180, 30);
    assert!(
        rendered.contains("generation=2 | 127.0.0.1 -> example.test:443 / evaluated=192.0.2.1:443")
    );
    assert!(
        rendered
            .contains("generation=3 | 127.0.0.1 -> example.test:443 / evaluated=[2001:db8::1]:443")
    );
    assert!(!rendered.contains("generation=1"));
    assert_eq!(model.rows()[0].traces.len(), 2);
    assert_eq!(model.rows()[0].traces[0].trace.policy_generation.get(), 2);
    assert!(
        matches!(model.rows()[0].traces[0].target, Some(EvaluationTarget::Resolved(ref facts)) if facts.resolved_ip() == "192.0.2.1".parse::<std::net::IpAddr>().unwrap())
    );
}

#[test]
fn older_ui_decision_events_report_missing_connection_facts() {
    let mut event = serde_json::to_value(decision_event(
        SessionId::new(),
        Some(TransactionId::new()),
        1,
    ))
    .unwrap();
    event.as_object_mut().unwrap().remove("target");
    let mut model = TuiModel::new(1, 2);
    model.apply(serde_json::from_value(event).unwrap());
    model.show_diagnostics();
    assert!(screen(&model, 120, 30).contains("connection: unavailable"));
}

#[test]
fn diagnostics_identifies_each_transaction_without_collapsing_evaluations() {
    let session = SessionId::new();
    let transactions = [
        TransactionId::new(),
        TransactionId::new(),
        TransactionId::new(),
    ];
    let targets = [
        "http://example.test:8080/first",
        "http://example.test:8080/second",
        "http://example.test:8080/second",
    ];
    let mut model = TuiModel::new(3, 8);
    for (index, (&transaction, target)) in transactions.iter().zip(targets).enumerate() {
        observe(&mut model, session, transaction, "POST", target);
        finding(
            &mut model,
            session,
            Some(transaction),
            &format!("fixture-{index}"),
        );
        decision(&mut model, session, Some(transaction), index as u64 + 1);
        decision(&mut model, session, Some(transaction), index as u64 + 1);
    }
    // A late response/evaluation for another request must not change the context.
    model.apply(UiEvent::HttpResponseObserved {
        session_id: session,
        transaction_id: transactions[0],
        status: 200,
        version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
    });
    decision(&mut model, session, Some(transactions[0]), 1);
    model.show_diagnostics();
    for index in (0..3).rev() {
        let screen = screen(&model, 120, 30);
        assert!(screen.contains(&format!("Transaction: {}", transactions[index])));
        assert!(screen.contains(&format!("Request: POST {} HTTP/1.1", targets[index])));
        assert!(screen.contains(&format!("finding fixture-{index}")));
        let evaluation = format!("decision Allow rule=<default> generation={}", index + 1);
        assert_eq!(
            screen.matches(&evaluation).count(),
            if index == 0 { 3 } else { 2 }
        );
        for other in (0..3).filter(|other| *other != index) {
            assert!(!screen.contains(&transactions[other].to_string()));
            assert!(!screen.contains(&format!("finding fixture-{other}")));
        }
        model.show_traffic();
        model.select_previous();
        model.show_diagnostics();
    }
}

#[test]
fn context_stays_visible_while_evidence_scrolls_and_expands() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 32);
    observe(
        &mut model,
        session,
        transaction,
        "GET",
        "http://example.test/items",
    );
    for generation in 1..=25 {
        decision(&mut model, session, Some(transaction), generation);
    }
    model.show_diagnostics();
    model.scroll_down(10);
    for expanded in [false, true] {
        if expanded {
            model.expand_focused_pane();
        }
        let screen = screen(&model, 120, 30);
        assert!(screen.contains(&format!("Transaction: {transaction}")));
        assert!(screen.contains("Request: GET http://example.test/items HTTP/1.1"));
        assert!(screen.contains("decision Allow rule=<default> generation=11"));
        assert!(!screen.contains("generation=1 "));
    }
    model.close_expanded_pane();
    model.scroll_up(10);
    assert!(screen(&model, 120, 30).contains("generation=1 "));
}

#[test]
fn long_targets_are_marked_and_bounded_at_minimum_size() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let target = format!("http://example.test:8080/{}end", "界e\u{301}".repeat(100));
    let mut model = TuiModel::new(1, 2);
    observe(&mut model, session, transaction, "GET", &target);
    decision(&mut model, session, Some(transaction), 1);
    model.show_diagnostics();

    let compact = screen(&model, 80, 24);
    assert!(compact.contains(&format!("Transaction: {transaction}")));
    assert!(compact.contains("Request: GET http://example.test:8080/"));
    assert!(compact.contains("... [shortened]"));
    assert!(compact.contains("decision Allow rule=<default> generation=1"));
    assert!(!compact.contains("end HTTP/1.1"));

    model.expand_focused_pane();
    let expanded = screen(&model, 80, 24);
    assert!(expanded.contains(&format!("Transaction: {transaction}")));
    assert!(expanded.contains("end HTTP/1.1"));
    assert!(expanded.contains("decision Allow rule=<default> generation=1"));
    assert!(expanded.matches('界').count() > compact.matches('界').count());
    // Rendering does not shorten or copy data into a new retained collection.
    assert_eq!(model.rows().len(), 1);
    assert_eq!(model.rows()[0].target, target);

    let huge_target = format!("http://example.test/{}", "x".repeat(16_000));
    observe(&mut model, session, transaction, "GET", &huge_target);
    let expanded = screen(&model, 80, 24);
    assert!(expanded.contains("... [shortened]"));
    assert!(expanded.contains("decision Allow rule=<default> generation=1"));
    assert!(screen(&model, 79, 23).contains("Terminal too small"));
}

#[test]
fn connect_uses_observed_authority_without_inventing_an_inner_url() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    observe(
        &mut model,
        session,
        transaction,
        "CONNECT",
        "example.test:443",
    );
    decision(&mut model, session, Some(transaction), 1);
    model.show_diagnostics();
    let screen = screen(&model, 80, 24);
    assert!(screen.contains(&format!("Transaction: {transaction}")));
    assert!(screen.contains("Request: CONNECT example.test:443 HTTP/1.1"));
    assert!(!screen.contains("https://"));
    assert!(!screen.contains("Host header:"));
}

#[test]
fn missing_and_late_metadata_never_borrows_another_requests_target() {
    let session = SessionId::new();
    let observed = TransactionId::new();
    let missing = TransactionId::new();
    let mut model = TuiModel::new(2, 2);
    model.apply(UiEvent::FlowOpened {
        session_id: session,
        client: "127.0.0.1:40000".to_owned(),
        target: "session-target.test:443".to_owned(),
    });
    observe(
        &mut model,
        session,
        observed,
        "GET",
        "http://other.test/private",
    );
    decision(&mut model, session, Some(missing), 7);
    model.select_next();
    model.show_diagnostics();
    let missing_screen = screen(&model, 120, 30);
    assert!(missing_screen.contains(&format!("Transaction: {missing}")));
    assert!(missing_screen.contains("Request: unavailable (not retained)"));
    assert!(missing_screen.contains("generation=7"));
    assert!(!missing_screen.contains("other.test"));
    assert!(!missing_screen.contains("session-target.test"));

    observe(
        &mut model,
        session,
        missing,
        "HEAD",
        "http://late.test/arrived",
    );
    let late = screen(&model, 120, 30);
    assert!(late.contains("Request: HEAD http://late.test/arrived HTTP/1.1"));
    assert!(late.contains("generation=7"));
    assert!(!late.contains("not retained"));
}

#[test]
fn evicted_request_metadata_is_not_reused_for_late_evidence() {
    let session = SessionId::new();
    let first = TransactionId::new();
    let second = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    observe(
        &mut model,
        session,
        first,
        "GET",
        "http://example.test/evicted",
    );
    model.apply(UiEvent::FlowClosed {
        session_id: session,
        client_to_upstream_bytes: 0,
        upstream_to_client_bytes: 0,
    });
    observe(
        &mut model,
        session,
        second,
        "POST",
        "http://example.test/retained",
    );
    decision(&mut model, session, Some(second), 2);
    decision(&mut model, session, Some(first), 1);
    model.show_diagnostics();
    let retained = screen(&model, 120, 30);
    assert!(retained.contains(&second.to_string()));
    assert!(!retained.contains("evicted"));
    assert!(!retained.contains("generation=1"));
    model.apply(UiEvent::FlowClosed {
        session_id: session,
        client_to_upstream_bytes: 0,
        upstream_to_client_bytes: 0,
    });
    decision(&mut model, session, Some(first), 3);
    assert!(screen(&model, 120, 30).contains("Original evaluation no longer retained"));
    model.show_traffic();
    model.show_diagnostics();
    let recreated = screen(&model, 120, 30);
    assert!(recreated.contains(&first.to_string()));
    assert!(recreated.contains("Request: unavailable (not retained)"));
    assert!(recreated.contains("generation=3"));
    assert!(!recreated.contains("/retained"));
    assert_eq!(model.rows().len(), 1);
}

#[test]
fn request_context_escapes_controls_and_labels_partial_targets() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    model.apply(UiEvent::HttpObserved {
        session_id: session,
        transaction_id: transaction,
        method: "GET".to_owned(),
        target: "/a\x1b[2J\r\n\t\u{0085}".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: vec![(
            "Host".to_owned(),
            b"example.test:8443\x1b\xc2\xa3\x1b\xff".to_vec(),
        )],
    });
    decision(&mut model, session, Some(transaction), 1);
    model.show_diagnostics();
    let escaped = screen(&model, 160, 30);
    assert!(escaped.contains("Host header: example.test:8443\\x1b£\\x1b\\xff"));
    assert!(escaped.contains("Request: GET /a\\x1b[2J"));
    assert!(escaped.contains("\\xc2\\x85 HTTP/1.1"));
    assert!(!escaped.chars().any(char::is_control));
    assert!(!escaped.contains("https://"));

    observe(&mut model, session, transaction, "GET", "/only-path");
    let partial = screen(&model, 120, 30);
    assert!(partial.contains("Host header: unavailable | Request: GET /only-path HTTP/1.1"));
    assert!(!partial.contains("example.test"));
}

#[test]
fn tcp_evidence_keeps_session_correlation_and_existing_layout() {
    let sessions = [SessionId::new(), SessionId::new()];
    let mut model = TuiModel::new(2, 2);
    decision(&mut model, sessions[0], None, 1);
    decision(&mut model, sessions[1], None, 2);
    model.show_diagnostics();
    for generation in [1, 2] {
        let screen = screen(&model, 80, 24);
        assert!(screen.contains(&format!("generation={generation}")));
        assert!(!screen.contains("Transaction:"));
        assert!(!screen.contains("Request:"));
        model.select_next();
    }
    assert_eq!(model.rows()[0].session_id, sessions[0]);
    assert_eq!(model.rows()[1].session_id, sessions[1]);
}

fn observe(
    model: &mut TuiModel,
    session: SessionId,
    transaction: TransactionId,
    method: &str,
    target: &str,
) {
    model.apply(UiEvent::HttpObserved {
        session_id: session,
        transaction_id: transaction,
        method: method.to_owned(),
        target: target.to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
    });
}

fn decision(
    model: &mut TuiModel,
    session: SessionId,
    transaction: Option<TransactionId>,
    generation: u64,
) {
    model.apply(decision_event(session, transaction, generation));
}

fn decision_event(
    session: SessionId,
    transaction: Option<TransactionId>,
    generation: u64,
) -> UiEvent {
    UiEvent::DecisionMade {
        evidence: None,
        session_id: session,
        transaction_id: transaction,
        trace: DecisionTrace {
            policy_generation: PolicyGeneration::new(generation).unwrap(),
            evaluated_stage: PolicyStage::HttpRequest,
            matched_rule: None,
            match_reasons: Vec::new(),
            final_action: EnforcementActionKind::Allow,
        },
        target: None,
    }
}

fn finding(
    model: &mut TuiModel,
    session: SessionId,
    transaction: Option<TransactionId>,
    detector: &str,
) {
    model.apply(UiEvent::FindingDetected {
        session_id: session,
        transaction_id: transaction,
        finding: Finding {
            detector_id: DetectorId::new(detector).unwrap(),
            severity: freja_domain::Severity::Low,
            confidence: Confidence::Confirmed,
            direction: Direction::HttpRequestBody,
            byte_range: None,
            evidence_hash: EvidenceHash::from_sha256([0; 32]),
            tags: Vec::new(),
        },
    });
}

fn screen(model: &TuiModel, width: u16, height: u16) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, model)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}
