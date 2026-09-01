use freja_policy::InspectionPattern;

use crate::{RawCapturePolicy, RawInspectionPattern, ValidationError};

/// Validated metadata-only or bounded-prefix capture policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePolicy {
    /// Store no raw payload bytes in audit or UI snapshots.
    MetadataOnly,
    /// Store a bounded raw prefix after the global body limit is enforced.
    Prefix {
        /// Maximum retained bytes per captured direction.
        max_bytes: usize,
    },
}

impl TryFrom<(RawCapturePolicy, usize)> for CapturePolicy {
    type Error = ValidationError;

    fn try_from((raw, body_prefix_bytes): (RawCapturePolicy, usize)) -> Result<Self, Self::Error> {
        match raw {
            RawCapturePolicy::MetadataOnly => Ok(Self::MetadataOnly),
            RawCapturePolicy::Prefix { max_bytes: 0 } => Err(ValidationError::ZeroLimit {
                name: "capture.max_bytes",
            }),
            RawCapturePolicy::Prefix { max_bytes } if max_bytes > body_prefix_bytes => {
                Err(ValidationError::CapturePrefixExceedsBodyLimit {
                    capture_bytes: max_bytes,
                    body_prefix_bytes,
                })
            }
            RawCapturePolicy::Prefix { max_bytes } => Ok(Self::Prefix { max_bytes }),
        }
    }
}

pub(super) fn validate_patterns(
    patterns: Vec<RawInspectionPattern>,
    body_prefix_bytes: usize,
) -> Result<Vec<InspectionPattern>, ValidationError> {
    patterns
        .into_iter()
        .map(|raw| validate_pattern(raw, body_prefix_bytes))
        .collect()
}

fn validate_pattern(
    raw: RawInspectionPattern,
    body_prefix_bytes: usize,
) -> Result<InspectionPattern, ValidationError> {
    let bytes =
        hex::decode(&raw.pattern_hex).map_err(|source| ValidationError::InvalidPatternHex {
            detector_id: raw.detector_id.clone(),
            source,
        })?;
    if bytes.len() > body_prefix_bytes {
        return Err(ValidationError::InspectionPatternExceedsBodyLimit {
            detector_id: raw.detector_id,
            pattern_bytes: bytes.len(),
            body_prefix_bytes,
        });
    }

    InspectionPattern::new(
        raw.detector_id,
        raw.rule_id,
        bytes,
        raw.severity,
        raw.confidence,
        raw.directions,
        raw.action,
        raw.tags,
    )
    .map_err(ValidationError::InvalidInspectionPattern)
}
