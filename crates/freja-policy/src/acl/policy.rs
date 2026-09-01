use std::{collections::HashSet, fmt};

use freja_domain::{
    Decision, DecisionTrace, EnforcementAction, HttpReject, MatchReason, PolicyGeneration,
    Protocol, RuleId, TcpClose, TcpCloseMode, TcpDetour,
};

use super::{AclRule, HttpHeaderMatcher, MatchExpression, PolicyError, PolicyFacts, RuleAction};

/// Immutable ordered first-match ACL and its policy generation.
#[derive(Debug, Clone)]
pub struct AclPolicy {
    generation: PolicyGeneration,
    rules: Vec<AclRule>,
    default_action: RuleAction,
}

impl AclPolicy {
    /// Validates rule identities and boolean expressions, then constructs a
    /// deterministic policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when rule IDs are duplicated or a rule contains
    /// an empty `all` or `any` expression.
    pub fn new(
        generation: PolicyGeneration,
        rules: Vec<AclRule>,
        default_action: RuleAction,
    ) -> Result<Self, PolicyError> {
        let mut rule_ids = HashSet::with_capacity(rules.len());
        for rule in &rules {
            if !rule_ids.insert(rule.id.clone()) {
                return Err(PolicyError::DuplicateRule {
                    rule_id: rule.id.clone(),
                });
            }
            validate_expression(&rule.id, &rule.matcher)?;
            if matches!(rule.action, RuleAction::Detour(_))
                && (!is_requested_stage_expression(&rule.matcher) || !requires_tcp(&rule.matcher))
            {
                return Err(PolicyError::InvalidDetourRule {
                    rule_id: rule.id.clone(),
                });
            }
        }
        if matches!(default_action, RuleAction::Detour(_)) {
            return Err(PolicyError::InvalidDefaultDetour);
        }
        Ok(Self {
            generation,
            rules,
            default_action,
        })
    }

    /// Returns this immutable policy snapshot's generation.
    pub const fn generation(&self) -> PolicyGeneration {
        self.generation
    }

    /// Evaluates rules in declaration order and stops at the first match.
    pub fn evaluate(&self, facts: PolicyFacts<'_>) -> Decision {
        for rule in &self.rules {
            if let ExpressionResult::Matched(reasons) = evaluate_expression(&rule.matcher, facts) {
                return decision(
                    self.generation,
                    facts,
                    &rule.action,
                    Some(rule.id.clone()),
                    reasons,
                );
            }
        }
        decision(
            self.generation,
            facts,
            &self.default_action,
            None,
            vec![MatchReason {
                criterion: "default-action".to_owned(),
                observed: format!("{:?}", self.default_action).to_ascii_lowercase(),
            }],
        )
    }
}

enum ExpressionResult {
    Matched(Vec<MatchReason>),
    DidNotMatch,
    Unavailable,
}

fn is_requested_stage_expression(expression: &MatchExpression) -> bool {
    match expression {
        MatchExpression::All(expressions) | MatchExpression::Any(expressions) => {
            expressions.iter().all(is_requested_stage_expression)
        }
        MatchExpression::Not(expression) => is_requested_stage_expression(expression),
        MatchExpression::DestinationIp(_)
        | MatchExpression::HttpMethod(_)
        | MatchExpression::HttpPathPrefix(_)
        | MatchExpression::HttpHeader(_) => false,
        MatchExpression::SourceIp(_)
        | MatchExpression::DestinationHost(_)
        | MatchExpression::DestinationPort(_)
        | MatchExpression::Protocol(_) => true,
    }
}

fn requires_tcp(expression: &MatchExpression) -> bool {
    match expression {
        MatchExpression::Protocol(Protocol::Tcp) => true,
        MatchExpression::All(expressions) => expressions.iter().any(requires_tcp),
        MatchExpression::Any(expressions) => {
            !expressions.is_empty() && expressions.iter().all(requires_tcp)
        }
        MatchExpression::Not(_)
        | MatchExpression::Protocol(Protocol::Http)
        | MatchExpression::SourceIp(_)
        | MatchExpression::DestinationIp(_)
        | MatchExpression::DestinationHost(_)
        | MatchExpression::DestinationPort(_)
        | MatchExpression::HttpMethod(_)
        | MatchExpression::HttpPathPrefix(_)
        | MatchExpression::HttpHeader(_) => false,
    }
}

fn validate_expression(rule_id: &RuleId, expression: &MatchExpression) -> Result<(), PolicyError> {
    match expression {
        MatchExpression::All(expressions) if expressions.is_empty() => {
            Err(PolicyError::EmptyBooleanExpression {
                rule_id: rule_id.clone(),
                operator: "all",
            })
        }
        MatchExpression::Any(expressions) if expressions.is_empty() => {
            Err(PolicyError::EmptyBooleanExpression {
                rule_id: rule_id.clone(),
                operator: "any",
            })
        }
        MatchExpression::All(expressions) | MatchExpression::Any(expressions) => {
            for expression in expressions {
                validate_expression(rule_id, expression)?;
            }
            Ok(())
        }
        MatchExpression::Not(expression) => validate_expression(rule_id, expression),
        _ => Ok(()),
    }
}

fn evaluate_expression(expression: &MatchExpression, facts: PolicyFacts<'_>) -> ExpressionResult {
    match expression {
        MatchExpression::All(expressions) => evaluate_all(expressions, facts),
        MatchExpression::Any(expressions) => evaluate_any(expressions, facts),
        MatchExpression::Not(expression) => match evaluate_expression(expression, facts) {
            ExpressionResult::Matched(_) => ExpressionResult::DidNotMatch,
            ExpressionResult::DidNotMatch => ExpressionResult::Matched(vec![MatchReason {
                criterion: "not".to_owned(),
                observed: "nested expression did not match".to_owned(),
            }]),
            ExpressionResult::Unavailable => ExpressionResult::Unavailable,
        },
        MatchExpression::SourceIp(network) => leaf(
            network.contains(&facts.requested().source_ip()),
            "source-ip",
            facts.requested().source_ip(),
        ),
        MatchExpression::DestinationIp(network) => facts
            .resolved_ip()
            .map_or(ExpressionResult::Unavailable, |address| {
                leaf(network.contains(&address), "destination-ip", address)
            }),
        MatchExpression::DestinationHost(pattern) => leaf(
            pattern.matches_target(facts.requested().requested_host()),
            "destination-host",
            facts.requested().requested_host(),
        ),
        MatchExpression::DestinationPort(range) => leaf(
            range.contains(facts.requested().destination_port()),
            "destination-port",
            facts.requested().destination_port(),
        ),
        MatchExpression::Protocol(protocol) => leaf(
            *protocol == facts.requested().protocol(),
            "protocol",
            format!("{:?}", facts.requested().protocol()).to_ascii_lowercase(),
        ),
        MatchExpression::HttpMethod(methods) => {
            facts.http().map_or(ExpressionResult::Unavailable, |http| {
                leaf(
                    methods
                        .iter()
                        .any(|method| method.eq_ignore_ascii_case(http.method())),
                    "http-method",
                    http.method(),
                )
            })
        }
        MatchExpression::HttpPathPrefix(prefix) => {
            facts.http().map_or(ExpressionResult::Unavailable, |http| {
                leaf(http.path().starts_with(prefix), "http-path", http.path())
            })
        }
        MatchExpression::HttpHeader(matcher) => evaluate_http_header(matcher, facts),
    }
}

fn evaluate_all(expressions: &[MatchExpression], facts: PolicyFacts<'_>) -> ExpressionResult {
    let mut reasons = Vec::new();
    let mut unavailable = false;
    for expression in expressions {
        match evaluate_expression(expression, facts) {
            ExpressionResult::Matched(nested) => reasons.extend(nested),
            ExpressionResult::DidNotMatch => return ExpressionResult::DidNotMatch,
            ExpressionResult::Unavailable => unavailable = true,
        }
    }
    if unavailable {
        ExpressionResult::Unavailable
    } else {
        ExpressionResult::Matched(reasons)
    }
}

fn evaluate_any(expressions: &[MatchExpression], facts: PolicyFacts<'_>) -> ExpressionResult {
    let mut unavailable = false;
    for expression in expressions {
        match evaluate_expression(expression, facts) {
            matched @ ExpressionResult::Matched(_) => return matched,
            ExpressionResult::DidNotMatch => {}
            ExpressionResult::Unavailable => unavailable = true,
        }
    }
    if unavailable {
        ExpressionResult::Unavailable
    } else {
        ExpressionResult::DidNotMatch
    }
}

fn evaluate_http_header(matcher: &HttpHeaderMatcher, facts: PolicyFacts<'_>) -> ExpressionResult {
    let Some(headers) = facts.http_headers() else {
        return ExpressionResult::Unavailable;
    };
    let Some(values) = headers.values(&matcher.name) else {
        return ExpressionResult::DidNotMatch;
    };
    let value_matches = matcher.value_contains.as_ref().is_none_or(|needle| {
        needle.is_empty()
            || values.iter().any(|value| {
                value
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
            })
    });
    leaf(
        value_matches,
        "http-header",
        matcher.name.to_ascii_lowercase(),
    )
}

fn leaf(observed: bool, criterion: &str, value: impl fmt::Display) -> ExpressionResult {
    if observed {
        ExpressionResult::Matched(vec![MatchReason {
            criterion: criterion.to_owned(),
            observed: value.to_string(),
        }])
    } else {
        ExpressionResult::DidNotMatch
    }
}

fn decision(
    generation: PolicyGeneration,
    facts: PolicyFacts<'_>,
    rule_action: &RuleAction,
    matched_rule: Option<RuleId>,
    match_reasons: Vec<MatchReason>,
) -> Decision {
    let action = match (rule_action, facts.requested().protocol()) {
        (RuleAction::Allow, _) => EnforcementAction::Allow,
        (RuleAction::Deny, Protocol::Http) => EnforcementAction::HttpReject(HttpReject::Forbidden),
        (RuleAction::Deny, Protocol::Tcp) => EnforcementAction::TcpClose(TcpClose {
            mode: TcpCloseMode::Graceful,
        }),
        (RuleAction::Detour(destination), Protocol::Tcp) => {
            EnforcementAction::TcpDetour(TcpDetour {
                destination: destination.clone(),
            })
        }
        (RuleAction::Detour(_), Protocol::Http) => {
            EnforcementAction::HttpReject(HttpReject::Forbidden)
        }
    };
    Decision {
        trace: DecisionTrace {
            policy_generation: generation,
            evaluated_stage: facts.stage(),
            matched_rule,
            match_reasons,
            final_action: action.kind(),
        },
        action,
    }
}
