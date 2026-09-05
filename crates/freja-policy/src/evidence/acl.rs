use serde::{Serialize, Serializer, ser::SerializeSeq};

use crate::{AclRule, RuleAction};

use super::DefinitionText;

/// Maximum declarations described in one ephemeral ACL evaluation view.
/// The combined declaration text has a separate 16 KiB limit.
pub const MAXIMUM_ACL_EVIDENCE_RULES: usize = 64;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum AclRuleResult {
    Matched,
    DidNotMatch,
    UnavailableAtThisStage,
    NotEvaluatedAfterFirstMatch,
}

/// Borrowed configuration and bounded outcomes from one actual ACL evaluation.
///
/// Construction belongs to the ACL evaluator. Outcomes are recorded as rules
/// execute, without re-evaluating expressions or retaining request facts.
#[derive(Debug, Clone, Copy)]
pub struct AclEvaluation<'a> {
    rules: &'a [AclRule],
    default_action: &'a RuleAction,
    results: [AclRuleResult; MAXIMUM_ACL_EVIDENCE_RULES],
    evaluated: usize,
    did_not_match: usize,
    unavailable: usize,
    selected: Option<usize>,
}

impl<'a> AclEvaluation<'a> {
    pub(crate) fn new(rules: &'a [AclRule], default_action: &'a RuleAction) -> Self {
        Self {
            rules,
            default_action,
            results: [AclRuleResult::NotEvaluatedAfterFirstMatch; MAXIMUM_ACL_EVIDENCE_RULES],
            evaluated: 0,
            did_not_match: 0,
            unavailable: 0,
            selected: None,
        }
    }

    pub(crate) fn record(&mut self, result: AclRuleResult) {
        if let Some(slot) = self.results.get_mut(self.evaluated) {
            *slot = result;
        }
        match result {
            AclRuleResult::Matched => self.selected = Some(self.evaluated),
            AclRuleResult::DidNotMatch => self.did_not_match += 1,
            AclRuleResult::UnavailableAtThisStage => self.unavailable += 1,
            AclRuleResult::NotEvaluatedAfterFirstMatch => {}
        }
        self.evaluated += 1;
    }

    pub(super) fn selected_rule(&self) -> Option<&'a AclRule> {
        self.selected.and_then(|index| self.rules.get(index))
    }

    pub(super) fn default_action(&self) -> &'a RuleAction {
        self.default_action
    }

    pub(super) fn snapshot(&self) -> AclEvidence {
        AclEvidence {
            rule_count: self.rules.len(),
            evaluated: self.evaluated,
            did_not_match: self.did_not_match,
            unavailable: self.unavailable,
            selected_ordinal: self.selected.map(|index| index + 1),
            default_action: DefinitionText::capture(self.default_action),
            declarations: DefinitionText::capture(&Declarations(self)),
        }
    }
}

struct Declarations<'a>(&'a AclEvaluation<'a>);

impl Serialize for Declarations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Declaration<'a> {
            order: usize,
            result: AclRuleResult,
            #[serde(flatten)]
            rule: &'a AclRule,
        }
        let rules = self.0.rules.iter().zip(self.0.results);
        let mut sequence = serializer.serialize_seq(Some(rules.len()))?;
        for (index, (rule, result)) in rules.enumerate() {
            sequence.serialize_element(&Declaration {
                order: index + 1,
                result,
                rule,
            })?;
        }
        sequence.end()
    }
}

/// Bounded configuration context, including rules that did not select the decision.
/// Counts describe the whole policy even when declaration text is truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEvidence {
    rule_count: usize,
    evaluated: usize,
    did_not_match: usize,
    unavailable: usize,
    selected_ordinal: Option<usize>,
    default_action: DefinitionText,
    declarations: DefinitionText,
}

impl AclEvidence {
    /// Number of configured declarations in this policy generation.
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Rules actually evaluated before the first match or fallback.
    pub const fn evaluated(&self) -> usize {
        self.evaluated
    }

    /// Evaluated expressions that were definitively false.
    pub const fn did_not_match(&self) -> usize {
        self.did_not_match
    }

    /// Expressions whose result needed facts unavailable at this stage.
    pub const fn unavailable(&self) -> usize {
        self.unavailable
    }

    /// One-based declaration position of the selected rule, or fallback.
    pub const fn selected_ordinal(&self) -> Option<usize> {
        self.selected_ordinal
    }

    /// Fallback action configured on the evaluated policy.
    pub const fn default_action(&self) -> &DefinitionText {
        &self.default_action
    }

    /// Ordered rule definitions and actual outcomes, bounded as one JSON field.
    /// At most [`MAXIMUM_ACL_EVIDENCE_RULES`] declarations are included; inspect
    /// [`Self::rule_count`] and [`DefinitionText::incomplete`] for omissions.
    pub const fn declarations(&self) -> &DefinitionText {
        &self.declarations
    }
}
