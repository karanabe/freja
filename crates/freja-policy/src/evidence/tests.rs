use super::{DefinitionText, MAXIMUM_DEFINITION_BYTES, RuleDefinition, RuleSource};
use crate::{AclPolicy, AclRule, MatchExpression, PolicyFacts, PortRange, RuleAction};
use freja_domain::{
    EnforcementMode, PolicyGeneration, Port, Protocol, RequestedTargetFacts, RuleId, TargetHost,
    UpstreamEndpoint,
};

#[test]
fn compound_definition_keeps_unmatched_branches_negation_range_and_action() {
    let rule = AclRule {
        id: RuleId::new("same-id").unwrap(),
        matcher: MatchExpression::All(vec![
            MatchExpression::Protocol(Protocol::Tcp),
            MatchExpression::Any(vec![
                MatchExpression::DestinationPort(
                    PortRange::new(Port::new(8000).unwrap(), Port::new(9000).unwrap()).unwrap(),
                ),
                MatchExpression::DestinationPort(PortRange::new(Port::HTTPS, Port::HTTPS).unwrap()),
            ]),
            MatchExpression::Not(Box::new(MatchExpression::SourceIp(
                "192.0.2.0/24".parse().unwrap(),
            ))),
        ]),
        action: RuleAction::Detour(UpstreamEndpoint::new(
            TargetHost::parse("fixture.test").unwrap(),
            Port::HTTPS,
        )),
    };
    let generation = PolicyGeneration::new(7).unwrap();
    let policy = AclPolicy::new(generation, vec![rule.clone()], RuleAction::Deny).unwrap();
    let facts = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::parse("localhost").unwrap(),
        Port::new(8080).unwrap(),
        Protocol::Tcp,
    );
    let (decision, definition) = policy.evaluate_with_definition(PolicyFacts::Requested(&facts));
    assert_eq!(decision, policy.evaluate(PolicyFacts::Requested(&facts)));
    let evidence = definition.snapshot(EnforcementMode::Observe);
    assert_eq!(evidence.source(), RuleSource::Acl);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(evidence.conditions().text()).unwrap(),
        serde_json::to_value(&rule.matcher).unwrap()
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(evidence.action().text()).unwrap(),
        serde_json::to_value(&rule.action).unwrap()
    );
    assert_eq!(
        decision
            .trace
            .match_reasons
            .iter()
            .filter(|reason| reason.criterion == "destination-port")
            .count(),
        1
    );
    assert!(evidence.conditions().text().contains("443"));
    assert!(evidence.conditions().text().contains("192.0.2.0/24"));
    assert!(evidence.action().text().contains("fixture.test"));
    assert!(!evidence.conditions().incomplete());
}

#[test]
fn truncation_is_bounded_and_unicode_safe_even_inside_a_value() {
    let text = "界\u{001b}".repeat(MAXIMUM_DEFINITION_BYTES);
    let field = DefinitionText::capture(&text);
    assert!(field.incomplete());
    assert!(field.text().len() <= MAXIMUM_DEFINITION_BYTES);
    assert!(!field.text().contains('\u{001b}'));
    let full = DefinitionText::capture(&"short");
    assert!(!full.incomplete());
    assert_eq!(full.text(), "\"short\"");
}

#[test]
fn default_has_no_individual_rule_and_snapshot_does_not_retain_policy() {
    let policy = AclPolicy::new(PolicyGeneration::default(), Vec::new(), RuleAction::Deny).unwrap();
    let facts = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::parse("localhost").unwrap(),
        Port::HTTPS,
        Protocol::Http,
    );
    let (decision, definition) = policy.evaluate_with_definition(PolicyFacts::Requested(&facts));
    let evidence = definition.snapshot(EnforcementMode::Enforce);
    drop(policy);
    assert!(decision.trace.matched_rule.is_none());
    assert_eq!(evidence.source(), RuleSource::AclDefault);
    assert_eq!(evidence.action().text(), "\"deny\"");
    let acl = evidence.acl().unwrap();
    assert_eq!(acl.rule_count(), 0);
    assert_eq!(acl.evaluated(), 0);
    assert_eq!(acl.default_action().text(), "\"deny\"");
    assert_eq!(acl.declarations().text(), "[]");
    assert_eq!(
        RuleDefinition::InspectionDefault
            .snapshot(EnforcementMode::Observe)
            .source(),
        RuleSource::InspectionDefault
    );
}

#[test]
fn inspection_uses_the_consumed_detector_even_when_rule_ids_collide() {
    use crate::{InspectionPattern, InspectionProgram};
    use freja_domain::{Confidence, DetectorId, Direction, Severity};
    let patterns = [
        ("first", b"FIRST".to_vec(), RuleAction::Deny),
        ("second", b"SECOND".to_vec(), RuleAction::Allow),
    ]
    .into_iter()
    .map(|(id, bytes, action)| {
        InspectionPattern::new(
            DetectorId::new(id).unwrap(),
            RuleId::new("shared-rule-id").unwrap(),
            bytes,
            Severity::High,
            Confidence::Confirmed,
            vec![Direction::HttpRequestBody],
            action,
            Vec::new(),
        )
        .unwrap()
    })
    .collect();
    let program = InspectionProgram::new(PolicyGeneration::default(), patterns).unwrap();
    let mut scanner = program.scanner(Direction::HttpRequestBody);
    let finding = scanner.inspect(b"SECOND").remove(0);
    let (decision, definition) = program.evaluate_with_definition(&finding, Protocol::Http);
    let evidence = definition.snapshot(EnforcementMode::Enforce);
    assert_eq!(
        decision.trace.matched_rule.as_ref().unwrap().as_str(),
        "shared-rule-id"
    );
    assert_eq!(evidence.source(), RuleSource::Inspection);
    assert_eq!(evidence.action().text(), "\"allow\"");
    let conditions: serde_json::Value = serde_json::from_str(evidence.conditions().text()).unwrap();
    assert_eq!(conditions["finding_detector_id_equals"], "second");
    assert_eq!(
        conditions["detector_definition"]["pattern_bytes_decimal"],
        serde_json::json!([83, 69, 67, 79, 78, 68])
    );
}

#[test]
fn acl_fallback_preserves_configuration_and_actual_unavailable_vs_false_results() {
    use freja_domain::{HttpRequestFacts, ResolvedTargetFacts, SanitizedHeaders};
    let rules = staged_acl_rules();
    let policy =
        AclPolicy::new(PolicyGeneration::default(), rules.clone(), RuleAction::Deny).unwrap();
    let requested = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::parse("public.test").unwrap(),
        Port::HTTPS,
        Protocol::Http,
    );
    let resolved = ResolvedTargetFacts::new(requested, "192.0.2.1".parse().unwrap());
    let facts = PolicyFacts::Resolved(&resolved);
    let (decision, definition) = policy.evaluate_with_definition(facts);
    assert_eq!(decision, policy.evaluate(facts));
    assert!(decision.trace.matched_rule.is_none());
    let snapshot = definition.snapshot(EnforcementMode::Observe);
    let acl = snapshot.acl().unwrap();
    assert_eq!(
        (
            acl.rule_count(),
            acl.evaluated(),
            acl.did_not_match(),
            acl.unavailable()
        ),
        (4, 4, 2, 2)
    );
    assert_eq!(acl.default_action().text(), "\"deny\"");
    let declarations: serde_json::Value = serde_json::from_str(acl.declarations().text()).unwrap();
    for (index, (rule, expected)) in rules
        .iter()
        .zip([
            "did-not-match",
            "unavailable-at-this-stage",
            "did-not-match",
            "unavailable-at-this-stage",
        ])
        .enumerate()
    {
        assert_eq!(declarations[index]["order"], index + 1);
        assert_eq!(declarations[index]["result"], expected);
        assert_eq!(declarations[index]["id"], rule.id.as_str());
        assert_eq!(
            declarations[index]["matcher"],
            serde_json::to_value(&rule.matcher).unwrap()
        );
        assert_eq!(
            declarations[index]["action"],
            serde_json::to_value(&rule.action).unwrap()
        );
    }
    let request = HttpRequestFacts::new(resolved, "GET", "/go", SanitizedHeaders::default());
    let (decision, definition) =
        policy.evaluate_with_definition(PolicyFacts::HttpRequest(&request));
    assert_eq!(decision.trace.matched_rule.as_ref(), Some(&rules[1].id));
    let selected = definition.snapshot(EnforcementMode::Observe);
    let acl = selected.acl().unwrap();
    assert_eq!(acl.selected_ordinal(), Some(2));
    assert_eq!(
        (acl.evaluated(), acl.did_not_match(), acl.unavailable()),
        (2, 1, 0)
    );
    let declarations: serde_json::Value = serde_json::from_str(acl.declarations().text()).unwrap();
    assert_eq!(declarations[1]["result"], "matched");
    assert_eq!(declarations[2]["result"], "not-evaluated-after-first-match");
    assert_eq!(declarations[3]["result"], "not-evaluated-after-first-match");
    drop(policy);
    assert!(
        snapshot
            .acl()
            .unwrap()
            .declarations()
            .text()
            .contains("internal.test")
    );
}

#[test]
fn acl_configuration_limits_keep_exact_totals_and_a_selected_rule_beyond_the_prefix() {
    use super::MAXIMUM_ACL_EVIDENCE_RULES;
    let count = MAXIMUM_ACL_EVIDENCE_RULES + 10;
    let mut rules: Vec<_> = (0..count)
        .map(|index| AclRule {
            id: RuleId::new(format!("rule-{index}")).unwrap(),
            matcher: MatchExpression::Protocol(Protocol::Tcp),
            action: RuleAction::Deny,
        })
        .collect();
    rules[count - 1].matcher = MatchExpression::Protocol(Protocol::Http);
    let policy = AclPolicy::new(PolicyGeneration::default(), rules, RuleAction::Deny).unwrap();
    let requested = RequestedTargetFacts::new(
        "127.0.0.1".parse().unwrap(),
        TargetHost::parse("fixture.test").unwrap(),
        Port::HTTPS,
        Protocol::Http,
    );
    let snapshot = policy
        .evaluate_with_definition(PolicyFacts::Requested(&requested))
        .1
        .snapshot(EnforcementMode::Observe);
    let acl = snapshot.acl().unwrap();
    assert_eq!(acl.rule_count(), count);
    assert_eq!(acl.evaluated(), count);
    assert_eq!(acl.did_not_match(), count - 1);
    assert_eq!(acl.selected_ordinal(), Some(count));
    let declarations: Vec<serde_json::Value> =
        serde_json::from_str(acl.declarations().text()).unwrap();
    assert_eq!(declarations.len(), MAXIMUM_ACL_EVIDENCE_RULES);
    assert_eq!(declarations.last().unwrap()["result"], "did-not-match");
    assert!(snapshot.conditions().text().contains("http"));
    assert!(!snapshot.conditions().incomplete());
    assert!(acl.declarations().text().len() <= MAXIMUM_DEFINITION_BYTES);
}

fn staged_acl_rules() -> Vec<AclRule> {
    use crate::HostPattern;
    use freja_domain::HostName;
    vec![
        AclRule {
            id: RuleId::new("private-host").unwrap(),
            matcher: MatchExpression::DestinationHost(HostPattern::Suffix(
                HostName::new("internal.test").unwrap(),
            )),
            action: RuleAction::Deny,
        },
        AclRule {
            id: RuleId::new("not-blocked-path").unwrap(),
            matcher: MatchExpression::Not(Box::new(MatchExpression::HttpPathPrefix(
                "/blocked".to_owned(),
            ))),
            action: RuleAction::Allow,
        },
        AclRule {
            id: RuleId::new("false-and-unavailable").unwrap(),
            matcher: MatchExpression::All(vec![
                MatchExpression::HttpMethod(["GET".to_owned()].into()),
                MatchExpression::Protocol(Protocol::Tcp),
            ]),
            action: RuleAction::Deny,
        },
        AclRule {
            id: RuleId::new("false-or-unavailable").unwrap(),
            matcher: MatchExpression::Any(vec![
                MatchExpression::HttpPathPrefix("/blocked".to_owned()),
                MatchExpression::Protocol(Protocol::Tcp),
            ]),
            action: RuleAction::Deny,
        },
    ]
}
