use freja_domain::{Confidence, DetectorId, Direction, InspectionMode, RuleId, Severity};
use freja_policy::RuleAction;
use serde::{Deserialize, Serialize};

/// Payload capture is disabled by default. Prefix capture remains explicitly bounded.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum RawCapturePolicy {
    #[default]
    MetadataOnly,
    Prefix {
        max_bytes: usize,
    },
}

/// Raw fixed-pattern detector and finding-policy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawInspection {
    pub mode: InspectionMode,
    pub patterns: Vec<RawInspectionPattern>,
}

/// One hexadecimal detector signature and its separate policy action.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInspectionPattern {
    pub detector_id: DetectorId,
    pub rule_id: RuleId,
    pub pattern_hex: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default = "default_directions")]
    pub directions: Vec<Direction>,
    #[serde(default = "default_action")]
    pub action: RuleAction,
    #[serde(default)]
    pub tags: Vec<String>,
}

const fn default_severity() -> Severity {
    Severity::High
}

const fn default_confidence() -> Confidence {
    Confidence::Confirmed
}

fn default_directions() -> Vec<Direction> {
    vec![
        Direction::ClientToUpstream,
        Direction::UpstreamToClient,
        Direction::HttpRequestBody,
        Direction::HttpResponseBody,
    ]
}

const fn default_action() -> RuleAction {
    RuleAction::Deny
}
