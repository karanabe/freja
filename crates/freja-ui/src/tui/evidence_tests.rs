use std::collections::VecDeque;

use freja_domain::{
    DecisionTrace, EnforcementActionKind, EnforcementMode, MatchReason, PolicyGeneration,
    PolicyStage, SessionId, TransactionId,
};
use freja_policy::{AclRule, MatchExpression, RuleAction, evidence::RuleDefinition};
use ratatui::{
    Terminal,
    backend::TestBackend,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
};

use super::{FocusPane, TuiModel, input::handle_key, render};
use crate::UiEvent;

fn key(model: &mut TuiModel, code: KeyCode) {
    assert!(!handle_key(
        KeyEvent::new(code, KeyModifiers::NONE),
        model,
        &mut VecDeque::new()
    ));
}

fn observe(model: &mut TuiModel, session: SessionId, transaction: TransactionId) {
    model.apply(UiEvent::HttpObserved {
        session_id: session,
        transaction_id: transaction,
        method: "GET".to_owned(),
        target: "http://fixture.test/same".to_owned(),
        version: "HTTP/1.1".to_owned(),
        headers: Vec::new(),
    });
}

fn acl_snapshot(
    rules: Vec<AclRule>,
    generation: u64,
) -> std::sync::Arc<freja_policy::evidence::RuleEvidence> {
    use freja_domain::{
        HttpRequestFacts, Port, Protocol, RequestedTargetFacts, ResolvedTargetFacts,
        SanitizedHeaders, TargetHost,
    };
    let policy = freja_policy::AclPolicy::new(
        PolicyGeneration::new(generation).unwrap(),
        rules,
        RuleAction::Allow,
    )
    .unwrap();
    let requested = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::parse("fixture.test").unwrap(),
        Port::HTTPS,
        Protocol::Http,
    );
    let request = HttpRequestFacts::new(
        ResolvedTargetFacts::new(requested, "192.0.2.1".parse().unwrap()),
        "GET",
        format!("/generation-{generation}"),
        SanitizedHeaders::default(),
    );
    policy
        .evaluate_with_definition(freja_policy::PolicyFacts::HttpRequest(&request))
        .1
        .snapshot(EnforcementMode::Observe)
}

fn decision(session: SessionId, transaction: TransactionId, generation: u64) -> UiEvent {
    let rule = AclRule {
        id: freja_domain::RuleId::new("same-id").unwrap(),
        matcher: MatchExpression::HttpPathPrefix(format!("/generation-{generation}")),
        action: RuleAction::Deny,
    };
    UiEvent::DecisionMade {
        session_id: session,
        transaction_id: Some(transaction),
        target: None,
        evidence: Some(acl_snapshot(vec![rule.clone()], generation)),
        trace: DecisionTrace {
            policy_generation: PolicyGeneration::new(generation).unwrap(),
            evaluated_stage: PolicyStage::HttpRequest,
            matched_rule: Some(rule.id),
            match_reasons: vec![MatchReason {
                criterion: "http-path".to_owned(),
                observed: "/same\x1b[2J".to_owned(),
            }],
            final_action: EnforcementActionKind::HttpReject,
        },
    }
}

fn screen(model: &TuiModel) -> String {
    screen_at(model, 120, 40)
}

fn screen_at(model: &TuiModel, width: u16, height: u16) -> String {
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

#[test]
fn normal_and_expanded_details_restore_identity_and_scroll_for_both_close_keys() {
    for expanded in [false, true] {
        for close in [KeyCode::Enter, KeyCode::Char('q')] {
            let session = SessionId::new();
            let transaction = TransactionId::new();
            let mut model = TuiModel::new(4, 8);
            observe(&mut model, session, transaction);
            for generation in 1..=3 {
                model.apply(decision(session, transaction, generation));
            }
            model.show_diagnostics();
            if expanded {
                key(&mut model, KeyCode::Char('z'));
            }
            key(&mut model, KeyCode::Char('j'));
            key(&mut model, KeyCode::Down);
            let selected = model.selected_evaluation().unwrap().id;
            let position = (model.diagnostics_scroll, model.evidence_view.scroll);
            let before = screen(&model);
            key(&mut model, KeyCode::Enter);
            let detail = screen(&model);
            assert!(detail.contains(&transaction.to_string()));
            assert!(detail.contains("generation=2"));
            assert!(detail.contains("/generation-2"));
            assert!(detail.contains("Configured action"));
            assert!(detail.contains("Recorded match reasons"));
            assert!(detail.contains("Observe"));
            assert!(detail.contains("not proof of execution"));
            assert!(detail.contains("\\x1b[2J"));
            assert!(!detail.contains('\x1b'));
            key(&mut model, close);
            assert_eq!(model.selected_evaluation().unwrap().id, selected);
            assert_eq!(
                (model.diagnostics_scroll, model.evidence_view.scroll),
                position
            );
            assert_eq!(
                model.expanded_pane(),
                expanded.then_some(FocusPane::Evidence)
            );
            assert_eq!(screen(&model), before);
            key(&mut model, KeyCode::Char('k'));
            assert_eq!(
                model
                    .selected_evaluation()
                    .unwrap()
                    .trace
                    .policy_generation
                    .get(),
                1
            );
        }
    }
}

#[test]
fn arrivals_reload_and_same_url_transactions_do_not_replace_open_or_selected_evaluation() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let other = TransactionId::new();
    let mut model = TuiModel::new(4, 4);
    observe(&mut model, session, transaction);
    model.apply(decision(session, transaction, 1));
    model.show_diagnostics();
    key(&mut model, KeyCode::Enter);
    let before = screen(&model);
    observe(&mut model, session, other);
    model.apply(decision(session, other, 2));
    model.apply(decision(session, transaction, 2));
    assert_eq!(screen(&model), before);
    key(&mut model, KeyCode::Char('q'));
    assert_eq!(
        model.evidence_row().unwrap().transaction_id,
        Some(transaction)
    );
    assert_eq!(
        model
            .selected_evaluation()
            .unwrap()
            .trace
            .policy_generation
            .get(),
        1
    );
    key(&mut model, KeyCode::Char('j'));
    key(&mut model, KeyCode::Enter);
    assert!(screen(&model).contains("/generation-2"));
}

#[test]
fn eviction_reports_loss_and_never_aliases_the_next_evaluation() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    observe(&mut model, session, transaction);
    model.apply(decision(session, transaction, 1));
    model.show_diagnostics();
    key(&mut model, KeyCode::Enter);
    model.apply(decision(session, transaction, 2));
    model.apply(decision(session, transaction, 3));
    assert!(screen(&model).contains("Original evaluation evicted"));
    assert!(screen(&model).contains("/generation-1"));
    key(&mut model, KeyCode::Enter);
    assert!(model.selected_evaluation().is_none());
    assert!(screen(&model).contains("Original evaluation no longer retained"));
    key(&mut model, KeyCode::Enter);
    assert!(model.evidence_view.detail.is_none());
    key(&mut model, KeyCode::Char('j'));
    assert_eq!(
        model
            .selected_evaluation()
            .unwrap()
            .trace
            .policy_generation
            .get(),
        2
    );
    key(&mut model, KeyCode::Enter);
    model.apply(UiEvent::FlowClosed {
        session_id: session,
        client_to_upstream_bytes: 0,
        upstream_to_client_bytes: 0,
    });
    let other = TransactionId::new();
    observe(&mut model, session, other);
    model.apply(decision(session, other, 4));
    assert!(screen(&model).contains("Original evaluation evicted"));
    key(&mut model, KeyCode::Char('q'));
    assert!(model.evidence_row().is_none());
}

#[test]
fn missing_definition_and_no_evaluation_are_explicit_and_definitions_are_not_serialized() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 4);
    observe(&mut model, session, transaction);
    model.show_diagnostics();
    key(&mut model, KeyCode::Enter);
    assert!(model.evidence_view.detail.is_none());
    assert!(screen(&model).contains("No evaluations retained"));
    let serialized = serde_json::to_string(&decision(session, transaction, 1)).unwrap();
    assert!(!serialized.contains("generation-1"));
    assert!(!serialized.contains("evidence"));
    model.apply(serde_json::from_str(&serialized).unwrap());
    key(&mut model, KeyCode::Enter);
    assert!(screen(&model).contains("unavailable (not retained with this evaluation)"));
    assert!(!screen(&model).contains("/generation-1"));
}

#[test]
fn oversized_definitions_and_reasons_remain_bounded_visible_and_scrollable() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut event = decision(session, transaction, 1);
    let rule = AclRule {
        id: freja_domain::RuleId::new("long").unwrap(),
        matcher: MatchExpression::Any(vec![
            MatchExpression::HttpPathPrefix("/generation-1".to_owned()),
            MatchExpression::HttpPathPrefix("界\u{0085}\x1b".repeat(20_000)),
        ]),
        action: RuleAction::Deny,
    };
    if let UiEvent::DecisionMade {
        evidence, trace, ..
    } = &mut event
    {
        *evidence = Some(acl_snapshot(vec![rule], 1));
        trace.match_reasons = vec![
            MatchReason {
                criterion: "long".to_owned(),
                observed: "x".repeat(2000)
            };
            100
        ];
    }
    let mut model = TuiModel::new(1, 2);
    observe(&mut model, session, transaction);
    model.apply(event);
    model.show_diagnostics();
    key(&mut model, KeyCode::Enter);
    let snapshot = &model.evidence_view.detail.as_ref().unwrap().snapshot;
    assert!(snapshot.reasons_incomplete);
    assert_eq!(snapshot.trace.match_reasons.len(), 64);
    assert!(snapshot.trace.match_reasons.capacity() <= 64);
    assert!(
        snapshot
            .trace
            .match_reasons
            .iter()
            .all(|reason| reason.observed.capacity() <= 1024)
    );
    let evidence = snapshot.evidence.as_ref().unwrap();
    assert!(evidence.conditions().incomplete());
    assert!(evidence.acl().unwrap().declarations().incomplete());
    assert!(
        evidence.acl().unwrap().declarations().text().len()
            <= freja_policy::evidence::MAXIMUM_DEFINITION_BYTES
    );
    assert!(screen(&model).contains("INCOMPLETE"));
    let mut reached_action = false;
    for _ in 0..100 {
        let text = screen(&model);
        assert!(!text.contains('\x1b'));
        assert!(!text.contains('\u{0085}'));
        reached_action |= text.contains("Configured action");
        key(&mut model, KeyCode::PageDown);
    }
    assert!(reached_action);
    key(&mut model, KeyCode::Home);
    assert!(screen(&model).contains("INCOMPLETE"));
}

#[test]
fn finding_only_row_cannot_open_a_rule_and_selection_survives_continuous_arrivals() {
    use freja_domain::{Confidence, DetectorId, Direction, EvidenceHash, Finding, Severity};
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 3);
    observe(&mut model, session, transaction);
    model.apply(UiEvent::FindingDetected {
        session_id: session,
        transaction_id: Some(transaction),
        finding: Finding {
            detector_id: DetectorId::new("same-id").unwrap(),
            severity: Severity::High,
            confidence: Confidence::Confirmed,
            direction: Direction::HttpRequestBody,
            byte_range: None,
            evidence_hash: EvidenceHash::from_sha256([0; 32]),
            tags: Vec::new(),
        },
    });
    model.show_diagnostics();
    key(&mut model, KeyCode::Char('j'));
    key(&mut model, KeyCode::Enter);
    assert!(model.evidence_view.detail.is_none());
    for generation in 1..=3 {
        model.apply(decision(session, transaction, generation));
    }
    key(&mut model, KeyCode::Char('j'));
    let selected = model.selected_evaluation().unwrap().id;
    model.apply(decision(session, transaction, 4));
    assert_eq!(model.selected_evaluation().unwrap().id, selected);
    let before = screen(&model);
    key(&mut model, KeyCode::Enter);
    key(&mut model, KeyCode::Char('q'));
    assert_eq!(screen(&model), before);
    model.apply(decision(session, transaction, 5));
    assert!(model.selected_evaluation().is_none());
}

#[test]
fn default_inspection_and_builtin_details_show_distinct_provenance() {
    use freja_domain::{Confidence, DetectorId, Direction, Severity};
    use freja_policy::InspectionPattern;
    let pattern = InspectionPattern::new(
        DetectorId::new("fixture").unwrap(),
        freja_domain::RuleId::new("same-id").unwrap(),
        b"FIXTURE".to_vec(),
        Severity::Low,
        Confidence::Confirmed,
        vec![Direction::HttpRequestBody],
        RuleAction::Deny,
        Vec::new(),
    )
    .unwrap();
    for (snapshot, source, condition, individual_rule) in [
        (
            acl_snapshot(Vec::new(), 1),
            "AclDefault",
            "no ACL rules were configured",
            false,
        ),
        (
            RuleDefinition::Inspection(&pattern).snapshot(EnforcementMode::Observe),
            "Inspection",
            "finding_detector_id_equals",
            true,
        ),
        (
            RuleDefinition::DestinationGuard("loopback = protect AND 127.0.0.0/8")
                .snapshot(EnforcementMode::Observe),
            "DestinationGuard",
            "127.0.0.0/8",
            true,
        ),
    ] {
        let session = SessionId::new();
        let transaction = TransactionId::new();
        let mut model = TuiModel::new(1, 2);
        observe(&mut model, session, transaction);
        let mut event = decision(session, transaction, 1);
        if let UiEvent::DecisionMade {
            evidence, trace, ..
        } = &mut event
        {
            *evidence = Some(snapshot);
            if !individual_rule {
                trace.matched_rule = None;
                trace.final_action = EnforcementActionKind::Allow;
            }
        }
        model.apply(event);
        model.show_diagnostics();
        key(&mut model, KeyCode::Enter);
        let text = screen(&model);
        assert!(text.contains(&format!("Source: {source}")));
        assert!(text.contains(condition));
        if !individual_rule {
            assert!(text.contains("<default: no individual rule>"));
        }
    }
}

#[test]
fn minimum_terminal_keeps_identity_and_all_detail_sections_reachable() {
    let session = SessionId::new();
    let transaction = TransactionId::new();
    let mut model = TuiModel::new(1, 2);
    observe(&mut model, session, transaction);
    model.apply(decision(session, transaction, 1));
    model.show_diagnostics();
    key(&mut model, KeyCode::Enter);
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let mut read = String::new();
    for _ in 0..5 {
        terminal.draw(|frame| render(frame, &model)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(text.contains(&transaction.to_string()));
        assert!(text.contains("generation=1"));
        read.push_str(&text);
        key(&mut model, KeyCode::PageDown);
    }
    assert!(read.contains("/generation-1"));
    assert!(read.contains("Configured action"));
    assert!(read.contains("Recorded match reasons"));
    assert!(read.contains("\\x1b[2J"));
    key(&mut model, KeyCode::Enter);
    assert!(model.evidence_view.detail.is_none());
}

#[test]
fn resolved_acl_detail_explains_empty_configuration_and_unmatched_configured_rules() {
    use freja_domain::{Port, Protocol, RequestedTargetFacts, ResolvedTargetFacts, TargetHost};
    use freja_policy::{AclPolicy, PolicyFacts, PortRange};
    for configured in [false, true] {
        let session = SessionId::new();
        let transaction = TransactionId::new();
        let mut model = TuiModel::new(1, 2);
        model.apply(UiEvent::HttpObserved {
            session_id: session,
            transaction_id: transaction,
            method: "CONNECT".to_owned(),
            target: "fixture.test:443".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
        });
        let rules = if configured {
            vec![
                AclRule {
                    id: freja_domain::RuleId::new("port-80-only").unwrap(),
                    matcher: MatchExpression::DestinationPort(
                        PortRange::new(Port::new(80).unwrap(), Port::new(80).unwrap()).unwrap(),
                    ),
                    action: RuleAction::Deny,
                },
                AclRule {
                    id: freja_domain::RuleId::new("private-path").unwrap(),
                    matcher: MatchExpression::HttpPathPrefix("/private".to_owned()),
                    action: RuleAction::Deny,
                },
            ]
        } else {
            Vec::new()
        };
        let policy = AclPolicy::new(PolicyGeneration::default(), rules, RuleAction::Allow).unwrap();
        let resolved = ResolvedTargetFacts::new(
            RequestedTargetFacts::new(
                "127.0.0.1".parse().unwrap(),
                TargetHost::parse("fixture.test").unwrap(),
                Port::HTTPS,
                Protocol::Http,
            ),
            "192.0.2.1".parse().unwrap(),
        );
        let (decision, definition) =
            policy.evaluate_with_definition(PolicyFacts::Resolved(&resolved));
        model.apply(UiEvent::DecisionMade {
            session_id: session,
            transaction_id: Some(transaction),
            trace: decision.trace,
            evidence: Some(definition.snapshot(EnforcementMode::Observe)),
            target: Some(freja_domain::EvaluationTarget::Resolved(resolved)),
        });
        model.show_diagnostics();
        key(&mut model, KeyCode::Enter);
        let first = screen(&model);
        let small = screen_at(&model, 80, 24);
        assert!(small.contains("Configured ACL:"));
        assert!(small.contains("Why default:"));
        assert!(small.contains("Unavailable at this stage: HTTP method/path/headers."));
        assert!(first.contains("stage=ResolvedDestination"));
        assert!(first.contains("default action: \"allow\""));
        assert!(first.contains("Unavailable at this stage: HTTP method/path/headers."));
        if configured {
            assert!(first.contains("Configured ACL: 2 rules"));
            assert!(first.contains("1 did not match | 1 unavailable at this stage"));
            assert!(first.contains("Why default: no configured rule matched"));
            let mut read = first;
            for _ in 0..10 {
                key(&mut model, KeyCode::PageDown);
                read.push_str(&screen(&model));
            }
            for expected in [
                "port-80-only",
                "private-path",
                "80",
                "/private",
                "did-not-match",
                "unavailable-at-this-stage",
                "deny",
            ] {
                assert!(read.contains(expected), "missing {expected}");
            }
        } else {
            assert!(first.contains("Configured ACL: 0 rules"));
            assert!(first.contains("Why default: no ACL rules were configured"));
            assert!(!first.contains("Conditions ("));
            assert!(first.contains("default-action: allow"));
        }
    }
}
