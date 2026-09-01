//! Ordered, first-match access-control policy.
//!
//! Facts are evaluated only at the lifecycle stage represented by
//! [`PolicyFacts`]. A criterion unavailable at that stage does not match, even
//! under negation. Callers must evaluate every DNS result independently.
//!
//! # Example
//!
//! ```
//! use std::net::IpAddr;
//! use freja_domain::{
//!     EnforcementAction, PolicyGeneration, Port, Protocol, RequestedTargetFacts,
//!     RuleId, TargetHost,
//! };
//! use freja_policy::{AclPolicy, AclRule, MatchExpression, PolicyFacts, RuleAction};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let rule = AclRule {
//!     id: RuleId::new("deny-tcp")?,
//!     matcher: MatchExpression::Protocol(Protocol::Tcp),
//!     action: RuleAction::Deny,
//! };
//! let policy = AclPolicy::new(PolicyGeneration::default(), vec![rule], RuleAction::Allow)?;
//! let facts = RequestedTargetFacts::new(
//!     IpAddr::from([127, 0, 0, 1]),
//!     TargetHost::parse("example.test")?,
//!     Port::new(443)?,
//!     Protocol::Tcp,
//! );
//!
//! let decision = policy.evaluate(PolicyFacts::Requested(&facts));
//! assert!(matches!(decision.action, EnforcementAction::TcpClose(_)));
//! assert_eq!(decision.trace.matched_rule.as_ref().map(RuleId::as_str), Some("deny-tcp"));
//! # Ok(())
//! # }
//! ```

mod error;
mod model;
mod policy;

pub use error::PolicyError;
pub use model::{
    AclRule, HostPattern, HttpHeaderMatcher, MatchExpression, PolicyFacts, PortRange, RuleAction,
};
pub use policy::AclPolicy;

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
