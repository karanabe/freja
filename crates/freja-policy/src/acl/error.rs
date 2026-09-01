use std::{error::Error, fmt};

use freja_domain::RuleId;

/// Failure to compile an ACL policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Two declaration-ordered rules used the same stable identity.
    DuplicateRule {
        /// Duplicated identity.
        rule_id: RuleId,
    },
    /// An `all` or `any` expression had no operands.
    EmptyBooleanExpression {
        /// Rule containing the invalid expression.
        rule_id: RuleId,
        /// Stable operator name (`all` or `any`).
        operator: &'static str,
    },
    /// An inclusive port range had zero or descending endpoints.
    InvalidPortRange {
        /// Requested lower endpoint.
        start: u16,
        /// Requested upper endpoint.
        end: u16,
    },
    /// A built-in security rule identity violated domain validation.
    BuiltInRule(freja_domain::IdError),
    /// A TCP detour rule could be evaluated too late or for a non-TCP flow.
    InvalidDetourRule {
        /// Invalid detour rule.
        rule_id: RuleId,
    },
    /// Detour was selected as a default despite requiring requested-stage TCP facts.
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
