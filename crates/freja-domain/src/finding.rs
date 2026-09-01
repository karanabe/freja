use serde::{Deserialize, Serialize};

use crate::DetectorId;

/// Direction in which inspected bytes travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Raw TCP bytes read from the client.
    ClientToUpstream,
    /// Raw TCP bytes read from the upstream.
    UpstreamToClient,
    /// Bytes belonging to an HTTP request body.
    HttpRequestBody,
    /// Bytes belonging to an HTTP response body.
    HttpResponseBody,
}

/// How body bytes become visible to inspection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionMode {
    /// Inspect a bounded body before forwarding any of it.
    Preflight,
    /// Inspect bounded state while forwarding chunks.
    #[default]
    Streaming,
}

/// Detector-assigned impact category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Context that does not imply harmful behavior.
    Informational,
    /// Low-impact behavior worth recording.
    Low,
    /// Material behavior that warrants review.
    Medium,
    /// High-impact behavior that normally warrants intervention.
    High,
    /// Highest-impact behavior requiring immediate attention.
    Critical,
}

/// Detector-assigned confidence in a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Weak signal that requires corroborating evidence.
    Heuristic,
    /// Strong but not definitive detector evidence.
    Probable,
    /// Deterministic evidence for the reported condition.
    Confirmed,
}

/// SHA-256 evidence digest. Raw evidence remains outside the default audit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EvidenceHash([u8; 32]);

impl EvidenceHash {
    /// Wraps a SHA-256 digest produced by an inspection implementation.
    pub const fn from_sha256(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An observation produced by a detector. Findings never execute enforcement directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that produced the observation.
    pub detector_id: DetectorId,
    /// Detector-assigned impact category.
    pub severity: Severity,
    /// Detector-assigned certainty; policy must not infer certainty from severity.
    pub confidence: Confidence,
    /// Flow direction in which evidence was found.
    pub direction: Direction,
    /// Half-open byte range in the direction's logical stream, when known.
    pub byte_range: Option<(u64, u64)>,
    /// SHA-256 digest retained instead of raw evidence by default.
    pub evidence_hash: EvidenceHash,
    /// Secret-free labels available to policy and audit consumers.
    pub tags: Vec<String>,
}
