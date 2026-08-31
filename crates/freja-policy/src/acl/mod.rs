use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt,
    net::IpAddr,
};

use freja_domain::{
    Decision, DecisionTrace, EnforcementAction, HostName, HttpReject, HttpRequestFacts,
    HttpResponseFacts, MatchReason, PolicyGeneration, PolicyStage, Port, Protocol,
    RequestedTargetFacts, ResolvedTargetFacts, RuleId, SanitizedHeaders, TargetHost, TcpClose,
    TcpCloseMode, TcpDetour, UpstreamEndpoint,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Failure to compile an ACL policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    DuplicateRule {
        rule_id: RuleId,
    },
    EmptyBooleanExpression {
        rule_id: RuleId,
        operator: &'static str,
    },
    InvalidPortRange {
        start: u16,
        end: u16,
    },
    BuiltInRule(freja_domain::IdError),
    InvalidDetourRule {
        rule_id: RuleId,
    },
    InvalidDefaultDetour,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRule { rule_id } => {
                write!(formatter, "policy rule ID {rule_id} is duplicated")
            }
            Self::EmptyBooleanExpression { rule_id, operator } => {
                write!(
                    formatter,
                    "rule {rule_id} has an empty {operator} expression"
                )
            }
            Self::InvalidPortRange { start, end } => {
                write!(formatter, "invalid destination port range {start}..={end}")
            }
            Self::BuiltInRule(_) => formatter.write_str("invalid built-in policy rule identifier"),
            Self::InvalidDetourRule { rule_id } => write!(
                formatter,
                "TCP detour rule {rule_id} must be limited to requested-stage TCP facts"
            ),
            Self::InvalidDefaultDetour => {
                formatter.write_str("TCP detour cannot be the policy default action")
            }
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BuiltInRule(source) => Some(source),
            Self::DuplicateRule { .. }
            | Self::EmptyBooleanExpression { .. }
            | Self::InvalidPortRange { .. }
            | Self::InvalidDetourRule { .. }
            | Self::InvalidDefaultDetour => None,
        }
    }
}

/// Inclusive, non-zero destination port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PortRangeRepr", into = "PortRangeRepr")]
pub struct PortRange {
    start: Port,
    end: Port,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct PortRangeRepr {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Creates an inclusive range with `start <= end`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::InvalidPortRange`] when `start` exceeds `end`.
    pub fn new(start: Port, end: Port) -> Result<Self, PolicyError> {
        if start.get() > end.get() {
            return Err(PolicyError::InvalidPortRange {
                start: start.get(),
                end: end.get(),
            });
        }
        Ok(Self { start, end })
    }

    /// Reports whether a port is inside the range.
    pub fn contains(self, port: Port) -> bool {
        (self.start.get()..=self.end.get()).contains(&port.get())
    }
}

impl TryFrom<PortRangeRepr> for PortRange {
    type Error = PolicyError;

    fn try_from(value: PortRangeRepr) -> Result<Self, Self::Error> {
        let start = Port::new(value.start).map_err(|_| PolicyError::InvalidPortRange {
            start: value.start,
            end: value.end,
        })?;
        let end = Port::new(value.end).map_err(|_| PolicyError::InvalidPortRange {
            start: value.start,
            end: value.end,
        })?;
        Self::new(start, end)
    }
}

impl From<PortRange> for PortRangeRepr {
    fn from(value: PortRange) -> Self {
        Self {
            start: value.start.get(),
            end: value.end.get(),
        }
    }
}

/// Exact or label-boundary suffix hostname matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum HostPattern {
    Exact(HostName),
    Suffix(HostName),
}

impl HostPattern {
    /// Reports whether a target matches this exact or label-boundary suffix pattern.
    pub fn matches_target(&self, target: &TargetHost) -> bool {
        let TargetHost::Name(candidate) = target else {
            return false;
        };
        match self {
            Self::Exact(expected) => candidate == expected,
            Self::Suffix(suffix) => {
                candidate == suffix
                    || candidate
                        .as_str()
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }
}

/// Case-insensitive header-name matcher with an optional value substring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeaderMatcher {
    pub name: String,
    #[serde(default)]
    pub value_contains: Option<String>,
}

/// Boolean ACL expression. Every matching leaf contributes a trace reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum MatchExpression {
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
    SourceIp(IpNet),
    DestinationIp(IpNet),
    DestinationHost(HostPattern),
    DestinationPort(PortRange),
    Protocol(Protocol),
    HttpMethod(BTreeSet<String>),
    HttpPathPrefix(String),
    HttpHeader(HttpHeaderMatcher),
}

/// Rule result before protocol-specific action selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    Allow,
    Deny,
    Detour(UpstreamEndpoint),
}

/// One ordered ACL rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    pub id: RuleId,
    pub matcher: MatchExpression,
    pub action: RuleAction,
}

/// Facts accepted by the ACL without a broad structure full of absent fields.
#[derive(Debug, Clone, Copy)]
pub enum PolicyFacts<'a> {
    Requested(&'a RequestedTargetFacts),
    Resolved(&'a ResolvedTargetFacts),
    HttpRequest(&'a HttpRequestFacts),
    HttpResponse(&'a HttpResponseFacts),
}

impl<'a> PolicyFacts<'a> {
    fn stage(self) -> PolicyStage {
        match self {
            Self::Requested(_) => PolicyStage::RequestedDestination,
            Self::Resolved(_) => PolicyStage::ResolvedDestination,
            Self::HttpRequest(_) => PolicyStage::HttpRequest,
            Self::HttpResponse(_) => PolicyStage::HttpResponse,
        }
    }

    fn requested(self) -> &'a RequestedTargetFacts {
        match self {
            Self::Requested(facts) => facts,
            Self::Resolved(facts) => facts.requested(),
            Self::HttpRequest(facts) => facts.target().requested(),
            Self::HttpResponse(facts) => facts.target().requested(),
        }
    }

    fn resolved_ip(self) -> Option<IpAddr> {
        match self {
            Self::Requested(_) => None,
            Self::Resolved(facts) => Some(facts.resolved_ip()),
            Self::HttpRequest(facts) => Some(facts.target().resolved_ip()),
            Self::HttpResponse(facts) => Some(facts.target().resolved_ip()),
        }
    }

    fn http(self) -> Option<&'a HttpRequestFacts> {
        match self {
            Self::HttpRequest(facts) => Some(facts),
            Self::Requested(_) | Self::Resolved(_) | Self::HttpResponse(_) => None,
        }
    }

    fn http_headers(self) -> Option<&'a SanitizedHeaders> {
        match self {
            Self::HttpRequest(facts) => Some(facts.headers()),
            Self::HttpResponse(facts) => Some(facts.headers()),
            Self::Requested(_) | Self::Resolved(_) => None,
        }
    }
}

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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::IpAddr};

    use freja_domain::{
        EnforcementAction, HostName, HttpRequestFacts, PolicyGeneration, Port, Protocol,
        RequestedTargetFacts, ResolvedTargetFacts, RuleId, SanitizedHeaders, TargetHost,
    };

    use super::{
        AclPolicy, AclRule, HostPattern, MatchExpression, PolicyError, PolicyFacts, RuleAction,
    };

    fn requested(host: &str) -> RequestedTargetFacts {
        RequestedTargetFacts::new(
            IpAddr::from([127, 0, 0, 1]),
            TargetHost::Name(HostName::new(host).unwrap()),
            Port::new(443).unwrap(),
            Protocol::Http,
        )
    }

    #[test]
    fn first_matching_rule_wins_and_is_explained() {
        let deny = AclRule {
            id: RuleId::new("deny-example").unwrap(),
            matcher: MatchExpression::DestinationHost(HostPattern::Suffix(
                HostName::new("example.test").unwrap(),
            )),
            action: RuleAction::Deny,
        };
        let allow = AclRule {
            id: RuleId::new("allow-all-http").unwrap(),
            matcher: MatchExpression::HttpMethod(BTreeSet::from(["GET".to_owned()])),
            action: RuleAction::Allow,
        };
        let policy = AclPolicy::new(
            PolicyGeneration::new(7).unwrap(),
            vec![deny, allow],
            RuleAction::Allow,
        )
        .unwrap();

        let facts = requested("api.example.test");
        let decision = policy.evaluate(PolicyFacts::Requested(&facts));

        assert!(matches!(decision.action, EnforcementAction::HttpReject(_)));
        assert_eq!(
            decision.trace.matched_rule.as_ref().map(RuleId::as_str),
            Some("deny-example")
        );
        assert_eq!(decision.trace.policy_generation.get(), 7);
    }

    #[test]
    fn duplicate_rule_ids_are_rejected() {
        let rule = AclRule {
            id: RuleId::new("duplicate").unwrap(),
            matcher: MatchExpression::Protocol(Protocol::Http),
            action: RuleAction::Allow,
        };

        let error = AclPolicy::new(
            PolicyGeneration::default(),
            vec![rule.clone(), rule],
            RuleAction::Allow,
        )
        .unwrap_err();

        assert!(matches!(error, PolicyError::DuplicateRule { .. }));
    }

    #[test]
    fn every_resolved_address_can_be_evaluated_independently() {
        let denied_network = "169.254.0.0/16".parse().unwrap();
        let rule = AclRule {
            id: RuleId::new("deny-link-local").unwrap(),
            matcher: MatchExpression::DestinationIp(denied_network),
            action: RuleAction::Deny,
        };
        let policy =
            AclPolicy::new(PolicyGeneration::default(), vec![rule], RuleAction::Allow).unwrap();
        let requested = requested("metadata.test");
        let public = ResolvedTargetFacts::new(requested.clone(), IpAddr::from([203, 0, 113, 4]));
        let link_local = ResolvedTargetFacts::new(requested, IpAddr::from([169, 254, 169, 254]));

        assert!(matches!(
            policy.evaluate(PolicyFacts::Resolved(&public)).action,
            EnforcementAction::Allow
        ));
        assert!(matches!(
            policy.evaluate(PolicyFacts::Resolved(&link_local)).action,
            EnforcementAction::HttpReject(_)
        ));
    }

    #[test]
    fn negation_does_not_treat_unavailable_stage_facts_as_a_mismatch() {
        let rule = AclRule {
            id: RuleId::new("deny-non-get").unwrap(),
            matcher: MatchExpression::Not(Box::new(MatchExpression::HttpMethod(BTreeSet::from([
                "GET".to_owned(),
            ])))),
            action: RuleAction::Deny,
        };
        let policy =
            AclPolicy::new(PolicyGeneration::default(), vec![rule], RuleAction::Allow).unwrap();
        let requested = requested("example.test");

        let early = policy.evaluate(PolicyFacts::Requested(&requested));
        assert!(matches!(early.action, EnforcementAction::Allow));
        assert!(early.trace.matched_rule.is_none());

        let resolved = ResolvedTargetFacts::new(requested, IpAddr::from([192, 0, 2, 10]));
        let post = HttpRequestFacts::new(resolved, "POST", "/upload", SanitizedHeaders::default());
        let decision = policy.evaluate(PolicyFacts::HttpRequest(&post));
        assert!(matches!(decision.action, EnforcementAction::HttpReject(_)));
        assert_eq!(
            decision.trace.matched_rule.as_ref().map(RuleId::as_str),
            Some("deny-non-get")
        );
    }
}
