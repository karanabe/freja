use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use freja_domain::{
    Decision, DecisionTrace, EnforcementAction, HttpReject, MatchReason, PolicyGeneration,
    PolicyStage, Protocol, ResolvedTargetFacts, RuleId, TcpClose, TcpCloseMode,
};
use serde::{Deserialize, Serialize};

use crate::{PolicyError, evidence::RuleDefinition};

/// Whether one sensitive address class is denied or explicitly permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DestinationAccess {
    /// Deny the address class after DNS resolution.
    #[default]
    Protect,
    /// Explicitly permit the address class, subject to remaining ACL policy.
    Allow,
}

/// Address-class controls compiled alongside ordered ACL rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DestinationGuardSettings {
    /// Protection for RFC 1918 and IPv6 unique-local addresses.
    pub private: DestinationAccess,
    /// Protection for IPv4 and IPv6 link-local addresses.
    pub link_local: DestinationAccess,
    /// Protection for loopback addresses.
    pub loopback: DestinationAccess,
    /// Protection for known cloud metadata-service addresses.
    pub metadata: DestinationAccess,
}

/// Deterministic protection for sensitive resolved destination classes.
#[derive(Debug, Clone)]
pub struct DestinationGuard {
    settings: DestinationGuardSettings,
    loopback_rule: RuleId,
    link_local_rule: RuleId,
    private_rule: RuleId,
    metadata_rule: RuleId,
    unroutable_rule: RuleId,
}

impl DestinationGuard {
    /// Compiles stable rule identities for destination protection.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] only if an internal built-in rule identifier is
    /// invalid, which indicates a Freja programming error.
    pub fn new(settings: DestinationGuardSettings) -> Result<Self, PolicyError> {
        Ok(Self {
            settings,
            loopback_rule: built_in_rule("protect-loopback-destination")?,
            link_local_rule: built_in_rule("protect-link-local-destination")?,
            private_rule: built_in_rule("protect-private-destination")?,
            metadata_rule: built_in_rule("protect-metadata-destination")?,
            unroutable_rule: built_in_rule("protect-unroutable-destination")?,
        })
    }

    /// Returns a denial when one resolved address belongs to a protected class.
    /// Unspecified and multicast addresses are always rejected.
    pub fn evaluate(
        &self,
        generation: PolicyGeneration,
        facts: &ResolvedTargetFacts,
    ) -> Option<Decision> {
        self.evaluate_with_definition(generation, facts)
            .map(|(decision, _)| decision)
    }

    /// Returns the actual built-in condition alongside its denial, without ACL lookup.
    pub fn evaluate_with_definition(
        &self,
        generation: PolicyGeneration,
        facts: &ResolvedTargetFacts,
    ) -> Option<(Decision, RuleDefinition<'_>)> {
        let address = facts.resolved_ip();
        let matched = if is_unroutable(address) {
            Some((
                &self.unroutable_rule,
                "unroutable",
                "resolved IPv4/IPv6 address is unspecified OR multicast; always protected",
            ))
        } else if is_metadata(address) && self.settings.metadata == DestinationAccess::Protect {
            Some((
                &self.metadata_rule,
                "metadata-service",
                "metadata = protect AND resolved address IN [169.254.169.254, 100.100.100.200, fd00:ec2::254]",
            ))
        } else if address.is_loopback() && self.settings.loopback == DestinationAccess::Protect {
            Some((
                &self.loopback_rule,
                "loopback",
                "loopback = protect AND resolved address IN [127.0.0.0/8, ::1/128]",
            ))
        } else if is_link_local(address) && self.settings.link_local == DestinationAccess::Protect {
            Some((
                &self.link_local_rule,
                "link-local",
                "link_local = protect AND resolved address IN [169.254.0.0/16, fe80::/10]",
            ))
        } else if is_private(address) && self.settings.private == DestinationAccess::Protect {
            Some((
                &self.private_rule,
                "private",
                "private = protect AND resolved address IN [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7]",
            ))
        } else {
            None
        };
        matched.map(|(rule, address_class, condition)| {
            (
                deny_decision(generation, facts, rule.clone(), address_class),
                RuleDefinition::DestinationGuard(condition),
            )
        })
    }
}

fn built_in_rule(value: &str) -> Result<RuleId, PolicyError> {
    RuleId::new(value).map_err(PolicyError::BuiltInRule)
}

fn deny_decision(
    generation: PolicyGeneration,
    facts: &ResolvedTargetFacts,
    matched_rule: RuleId,
    address_class: &str,
) -> Decision {
    let action = match facts.requested().protocol() {
        Protocol::Http => EnforcementAction::HttpReject(HttpReject::Forbidden),
        Protocol::Tcp => EnforcementAction::TcpClose(TcpClose {
            mode: TcpCloseMode::Graceful,
        }),
    };
    Decision {
        trace: DecisionTrace {
            policy_generation: generation,
            evaluated_stage: PolicyStage::ResolvedDestination,
            matched_rule: Some(matched_rule),
            match_reasons: vec![MatchReason {
                criterion: "destination-address-class".to_owned(),
                observed: format!("{} ({address_class})", facts.resolved_ip()),
            }],
            final_action: action.kind(),
        },
        action,
    }
}

fn is_unroutable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_unspecified() || address.is_multicast(),
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    }
}

fn is_metadata(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address == Ipv4Addr::new(169, 254, 169, 254)
                || address == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(address) => address == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use freja_domain::{
        EnforcementAction, PolicyGeneration, Port, Protocol, RequestedTargetFacts,
        ResolvedTargetFacts, RuleId, TargetHost,
    };

    use super::{DestinationAccess, DestinationGuard, DestinationGuardSettings};

    fn resolved(address: [u8; 4]) -> ResolvedTargetFacts {
        ResolvedTargetFacts::new(
            RequestedTargetFacts::new(
                IpAddr::from([127, 0, 0, 1]),
                TargetHost::Ip(IpAddr::from(address)),
                Port::new(80).unwrap(),
                Protocol::Tcp,
            ),
            IpAddr::from(address),
        )
    }

    #[test]
    fn metadata_is_explained_before_link_local() {
        let guard = DestinationGuard::new(DestinationGuardSettings::default()).unwrap();
        let decision = guard
            .evaluate(PolicyGeneration::default(), &resolved([169, 254, 169, 254]))
            .unwrap();

        assert!(matches!(decision.action, EnforcementAction::TcpClose(_)));
        assert_eq!(
            decision.trace.matched_rule.as_ref().map(RuleId::as_str),
            Some("protect-metadata-destination")
        );
    }

    #[test]
    fn explicit_loopback_access_allows_local_test_servers() {
        let guard = DestinationGuard::new(DestinationGuardSettings {
            loopback: DestinationAccess::Allow,
            ..DestinationGuardSettings::default()
        })
        .unwrap();

        assert!(
            guard
                .evaluate(PolicyGeneration::default(), &resolved([127, 0, 0, 1]))
                .is_none()
        );
    }
}
