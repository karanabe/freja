use serde::{Deserialize, Serialize};

use crate::DetectorId;

/// Direction in which inspected bytes travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    ClientToUpstream,
    UpstreamToClient,
    HttpRequestBody,
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
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

/// Detector-assigned confidence in a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Heuristic,
    Probable,
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
    pub detector_id: DetectorId,
    pub severity: Severity,
    pub confidence: Confidence,
    pub direction: Direction,
    pub byte_range: Option<(u64, u64)>,
    pub evidence_hash: EvidenceHash,
    pub tags: Vec<String>,
}
