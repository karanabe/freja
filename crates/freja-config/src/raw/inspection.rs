use freja_domain::{Confidence, DetectorId, Direction, InspectionMode, RuleId, Severity};
use freja_policy::RuleAction;
use serde::{Deserialize, Serialize};

/// Payload capture is disabled by default. Prefix capture remains explicitly bounded.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum RawCapturePolicy {
    /// Retain metadata and evidence hashes without raw payload bytes.
    #[default]
    MetadataOnly,
    /// Retain at most a bounded prefix from each configured direction.
    Prefix {
        /// Maximum retained prefix length in bytes.
        max_bytes: usize,
    },
}

/// Raw fixed-pattern detector and finding-policy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawInspection {
    /// Whether inspection completes before forwarding or runs over streamed chunks.
    pub mode: InspectionMode,
    /// Fixed byte patterns compiled during configuration compilation.
    pub patterns: Vec<RawInspectionPattern>,
}

/// One hexadecimal detector signature and its separate policy action.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInspectionPattern {
    /// Stable detector identity included in findings.
    pub detector_id: DetectorId,
    /// Stable policy rule identity included in resulting decision traces.
    pub rule_id: RuleId,
    /// Byte signature encoded as hexadecimal text.
    pub pattern_hex: String,
    #[serde(default = "default_severity")]
    /// Impact assigned to a match; defaults to high.
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    /// Certainty assigned to a match; defaults to confirmed.
    pub confidence: Confidence,
    #[serde(default = "default_directions")]
    /// Stream directions in which this detector runs.
    pub directions: Vec<Direction>,
    #[serde(default = "default_action")]
    /// Policy action considered after the detector produces a finding.
    pub action: RuleAction,
    #[serde(default)]
    /// Secret-free labels copied into findings.
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
