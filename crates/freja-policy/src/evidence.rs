//! Bounded, ephemeral definitions supplied by the evaluator that selected them.
//!
//! This view is deliberately not serializable as an audit event. It contains
//! sensitive live policy values and belongs only in local UI memory.

use std::{collections::BTreeSet, io, sync::Arc};

use freja_domain::{EnforcementMode, Port};
use serde::Serialize;

use crate::{InspectionPattern, RuleAction};

mod acl;
pub(crate) use acl::AclRuleResult;
pub use acl::{AclEvaluation, AclEvidence, MAXIMUM_ACL_EVIDENCE_RULES};

/// Maximum retained UTF-8 bytes in each definition field (conditions or action).
pub const MAXIMUM_DEFINITION_BYTES: usize = 16 * 1024;

/// The evaluator that supplied a definition, independent of rule ID spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    /// First matching declaration-ordered ACL rule.
    Acl,
    /// ACL fallback with no individual rule.
    AclDefault,
    /// A finding consumed by the inspection program's policy.
    Inspection,
    /// Unknown detector allowed by the inspection program.
    InspectionDefault,
    /// Built-in resolved address protection, independent of ACL order.
    DestinationGuard,
    /// The listener's built-in CONNECT port allowlist.
    ConnectPorts,
}

/// A bounded definition field, with explicit loss information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionText {
    text: Box<str>,
    incomplete: bool,
}

impl DefinitionText {
    /// Retained JSON, or a JSON prefix when [`Self::incomplete`] is true.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// A size limit or serialization failure prevented retaining the whole field.
    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }

    fn capture(value: &impl Serialize) -> Self {
        let mut writer = LimitedWriter(Vec::new());
        let incomplete = serde_json::to_writer_pretty(&mut writer, value).is_err();
        // A limit can split a UTF-8 scalar. Keep only the valid prefix.
        let length = match std::str::from_utf8(&writer.0) {
            Ok(text) => text.len(),
            Err(error) => error.valid_up_to(),
        };
        writer.0.truncate(length);
        Self {
            text: String::from_utf8(writer.0)
                .unwrap_or_default()
                .into_boxed_str(),
            incomplete,
        }
    }
}

struct LimitedWriter(Vec<u8>);

impl io::Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = MAXIMUM_DEFINITION_BYTES.saturating_sub(self.0.len());
        let retained = bytes.len().min(remaining);
        self.0.extend_from_slice(&bytes[..retained]);
        if retained < bytes.len() {
            return Err(io::Error::other("definition retention limit"));
        }
        Ok(retained)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Immutable local UI evidence paired with one decision, never a policy archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleEvidence {
    source: RuleSource,
    conditions: DefinitionText,
    action: DefinitionText,
    enforcement: EnforcementMode,
    acl: Option<AclEvidence>,
}

impl RuleEvidence {
    /// Evaluator provenance, supplied without a rule-ID lookup.
    pub const fn source(&self) -> RuleSource {
        self.source
    }

    /// Full condition expression, or an explicitly incomplete prefix.
    pub const fn conditions(&self) -> &DefinitionText {
        &self.conditions
    }

    /// Configured action including a detour destination when applicable.
    pub const fn action(&self) -> &DefinitionText {
        &self.action
    }

    /// Enforcement mode of the snapshot used for this decision.
    pub const fn enforcement(&self) -> EnforcementMode {
        self.enforcement
    }

    /// Configuration and evaluation outcomes for an ACL decision, including fallback.
    pub const fn acl(&self) -> Option<&AclEvidence> {
        self.acl.as_ref()
    }
}

/// Borrowed definition returned together with an evaluation result.
///
/// Callers must preserve that pairing. Snapshot only for an attached UI; the
/// resulting bounded value cannot retain the policy or any previous generation.
#[derive(Debug, Clone, Copy)]
pub enum RuleDefinition<'a> {
    /// The evaluated ACL configuration and its actual declaration outcomes.
    Acl(AclEvaluation<'a>),
    /// The pattern policy selected by the actual finding evaluator.
    Inspection(&'a InspectionPattern),
    /// No pattern policy matched the finding's detector.
    InspectionDefault,
    /// Built-in condition supplied at the guard's matching branch.
    DestinationGuard(&'static str),
    /// CONNECT denial because the port is outside this listener allowlist.
    ConnectPorts(&'a BTreeSet<Port>),
}

impl RuleDefinition<'_> {
    /// Copies bounded definition fields for best-effort local presentation.
    /// ACL context adds one jointly bounded declaration list and the default action.
    /// Serialization failure affects only this view, never policy evaluation.
    pub fn snapshot(self, enforcement: EnforcementMode) -> Arc<RuleEvidence> {
        let (source, conditions, action) = match self {
            Self::Acl(evaluation) => match evaluation.selected_rule() {
                Some(rule) => (
                    RuleSource::Acl,
                    DefinitionText::capture(&rule.matcher),
                    DefinitionText::capture(&rule.action),
                ),
                None => (
                    RuleSource::AclDefault,
                    DefinitionText::capture(
                        &"No ACL rule selected; see configured ACL and outcomes",
                    ),
                    DefinitionText::capture(evaluation.default_action()),
                ),
            },
            Self::Inspection(pattern) => (
                RuleSource::Inspection,
                DefinitionText::capture(&pattern.definition_conditions()),
                DefinitionText::capture(pattern.action()),
            ),
            Self::InspectionDefault => (
                RuleSource::InspectionDefault,
                DefinitionText::capture(&"No pattern policy for this detector; no individual rule"),
                DefinitionText::capture(&RuleAction::Allow),
            ),
            Self::DestinationGuard(condition) => (
                RuleSource::DestinationGuard,
                DefinitionText::capture(&condition),
                DefinitionText::capture(&RuleAction::Deny),
            ),
            Self::ConnectPorts(ports) => (
                RuleSource::ConnectPorts,
                DefinitionText::capture(&("CONNECT destination port NOT IN allowed ports", ports)),
                DefinitionText::capture(&RuleAction::Deny),
            ),
        };
        Arc::new(RuleEvidence {
            source,
            conditions,
            action,
            enforcement,
            acl: match self {
                Self::Acl(evaluation) => Some(evaluation.snapshot()),
                _ => None,
            },
        })
    }
}

#[cfg(test)]
mod tests;
