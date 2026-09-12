use std::{error::Error, fmt};

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

/// A non-empty half-open byte range in a logical stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "(u64, u64)", into = "(u64, u64)")]
pub struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    /// Creates a half-open range whose end is strictly greater than its start.
    ///
    /// # Errors
    ///
    /// Returns [`ByteRangeError`] for an empty or reversed range.
    pub const fn new(start: u64, end: u64) -> Result<Self, ByteRangeError> {
        if start >= end {
            return Err(ByteRangeError { start, end });
        }
        Ok(Self { start, end })
    }

    /// Returns the inclusive start offset.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the exclusive end offset.
    pub const fn end(self) -> u64 {
        self.end
    }
}

impl TryFrom<(u64, u64)> for ByteRange {
    type Error = ByteRangeError;

    fn try_from((start, end): (u64, u64)) -> Result<Self, Self::Error> {
        Self::new(start, end)
    }
}

impl From<ByteRange> for (u64, u64) {
    fn from(range: ByteRange) -> Self {
        (range.start(), range.end())
    }
}

/// An empty or reversed half-open byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRangeError {
    start: u64,
    end: u64,
}

impl ByteRangeError {
    /// Returns the rejected inclusive start offset.
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the rejected exclusive end offset.
    pub const fn end(self) -> u64 {
        self.end
    }
}

impl fmt::Display for ByteRangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "byte range end {} must be greater than start {}",
            self.end, self.start
        )
    }
}

impl Error for ByteRangeError {}

/// An observation produced by a detector. Findings never execute enforcement directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Detector that produced the observation.
    detector_id: DetectorId,
    /// Detector-assigned impact category.
    severity: Severity,
    /// Detector-assigned certainty; policy must not infer certainty from severity.
    confidence: Confidence,
    /// Flow direction in which evidence was found.
    direction: Direction,
    /// Half-open byte range in the direction's logical stream, when known.
    byte_range: Option<ByteRange>,
    /// SHA-256 digest retained instead of raw evidence by default.
    evidence_hash: EvidenceHash,
    /// Secret-free labels available to policy and audit consumers.
    tags: Box<[String]>,
}

impl Finding {
    /// Creates one immutable detector observation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        detector_id: DetectorId,
        severity: Severity,
        confidence: Confidence,
        direction: Direction,
        byte_range: Option<ByteRange>,
        evidence_hash: EvidenceHash,
        tags: Vec<String>,
    ) -> Self {
        Self {
            detector_id,
            severity,
            confidence,
            direction,
            byte_range,
            evidence_hash,
            tags: tags.into_boxed_slice(),
        }
    }

    /// Returns the detector identity.
    pub const fn detector_id(&self) -> &DetectorId {
        &self.detector_id
    }

    /// Returns the detector-assigned impact category.
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Returns the detector-assigned confidence.
    pub const fn confidence(&self) -> Confidence {
        self.confidence
    }

    /// Returns the logical stream direction in which evidence was observed.
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Returns the non-empty observed byte range, when known.
    pub const fn byte_range(&self) -> Option<ByteRange> {
        self.byte_range
    }

    /// Returns the digest retained in place of raw evidence.
    pub const fn evidence_hash(&self) -> EvidenceHash {
        self.evidence_hash
    }

    /// Returns the immutable secret-free detector labels.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }
}

#[cfg(test)]
mod tests {
    use super::ByteRange;

    #[test]
    fn byte_range_rejects_empty_and_reversed_bounds() {
        assert!(ByteRange::new(4, 4).is_err());
        assert!(ByteRange::new(5, 4).is_err());
        let range = ByteRange::new(4, 5).unwrap();
        assert_eq!((range.start(), range.end()), (4, 5));
        assert!(serde_json::from_str::<ByteRange>("[4,4]").is_err());
    }
}
