use std::{error::Error, fmt};

use freja_domain::RuleId;

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
