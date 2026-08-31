use std::{collections::HashSet, error::Error, fmt, sync::Arc};

use freja_domain::{
    Confidence, Decision, DecisionTrace, DetectorId, Direction, EnforcementAction, EvidenceHash,
    Finding, HttpReject, MatchReason, PolicyGeneration, PolicyStage, Protocol, RuleId, Severity,
    TcpClose, TcpCloseMode,
};
use sha2::{Digest, Sha256};

use crate::RuleAction;

/// Invalid fixed-pattern inspection configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionError {
    EmptyPattern { detector_id: DetectorId },
    EmptyDirections { detector_id: DetectorId },
    DuplicateDetector { detector_id: DetectorId },
    UnsupportedDetour { detector_id: DetectorId },
}

impl fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPattern { detector_id } => {
                write!(
                    formatter,
                    "detector {detector_id} has an empty byte pattern"
                )
            }
            Self::EmptyDirections { detector_id } => {
                write!(
                    formatter,
                    "detector {detector_id} has no inspection directions"
                )
            }
            Self::DuplicateDetector { detector_id } => {
                write!(formatter, "detector ID {detector_id} is duplicated")
            }
            Self::UnsupportedDetour { detector_id } => write!(
                formatter,
                "detector {detector_id} cannot detour a flow after inspection begins"
            ),
        }
    }
}

impl Error for InspectionError {}

/// Validated fixed byte signature and the separate policy rule consuming its findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionPattern {
    detector_id: DetectorId,
    rule_id: RuleId,
    bytes: Box<[u8]>,
    severity: Severity,
    confidence: Confidence,
    directions: Box<[Direction]>,
    action: RuleAction,
    tags: Box<[String]>,
}

impl InspectionPattern {
    /// Validates one detector and its corresponding finding-policy rule.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError`] when the signature or direction set is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        detector_id: DetectorId,
        rule_id: RuleId,
        bytes: Vec<u8>,
        severity: Severity,
        confidence: Confidence,
        directions: Vec<Direction>,
        action: RuleAction,
        tags: Vec<String>,
    ) -> Result<Self, InspectionError> {
        if bytes.is_empty() {
            return Err(InspectionError::EmptyPattern { detector_id });
        }
        if directions.is_empty() {
            return Err(InspectionError::EmptyDirections { detector_id });
        }
        if matches!(action, RuleAction::Detour(_)) {
            return Err(InspectionError::UnsupportedDetour { detector_id });
        }
        Ok(Self {
            detector_id,
            rule_id,
            bytes: bytes.into_boxed_slice(),
            severity,
            confidence,
            directions: directions.into_boxed_slice(),
            action,
            tags: tags.into_boxed_slice(),
        })
    }

    pub fn detector_id(&self) -> &DetectorId {
        &self.detector_id
    }

    /// Returns the fixed signature length retained by streaming scanners.
    pub const fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    fn applies_to(&self, direction: Direction) -> bool {
        self.directions.contains(&direction)
    }
}

/// Immutable detector set and finding policy for one policy generation.
#[derive(Debug, Clone)]
pub struct InspectionProgram {
    generation: PolicyGeneration,
    patterns: Arc<[InspectionPattern]>,
    maximum_pattern_bytes: usize,
}

impl InspectionProgram {
    /// Compiles fixed patterns and rejects ambiguous detector identities.
    ///
    /// # Errors
    ///
    /// Returns [`InspectionError::DuplicateDetector`] when two detectors share an ID.
    pub fn new(
        generation: PolicyGeneration,
        patterns: Vec<InspectionPattern>,
    ) -> Result<Self, InspectionError> {
        let mut detector_ids = HashSet::with_capacity(patterns.len());
        let mut maximum_pattern_bytes = 0;
        for pattern in &patterns {
            if !detector_ids.insert(pattern.detector_id.clone()) {
                return Err(InspectionError::DuplicateDetector {
                    detector_id: pattern.detector_id.clone(),
                });
            }
            maximum_pattern_bytes = maximum_pattern_bytes.max(pattern.bytes.len());
        }
        Ok(Self {
            generation,
            patterns: patterns.into(),
            maximum_pattern_bytes,
        })
    }

    /// Creates a no-op program for configurations without detectors.
    pub fn empty(generation: PolicyGeneration) -> Self {
        Self {
            generation,
            patterns: Arc::from([]),
            maximum_pattern_bytes: 0,
        }
    }

    /// Creates independent per-flow matching state for one traffic direction.
    pub fn scanner(&self, direction: Direction) -> StreamScanner {
        StreamScanner {
            program: self.clone(),
            direction,
            carry: Vec::new(),
            processed_bytes: 0,
        }
    }

    /// Turns a detector finding into a protocol-aware policy decision.
    pub fn evaluate(&self, finding: &Finding, protocol: Protocol) -> Decision {
        let matched = self
            .patterns
            .iter()
            .find(|pattern| pattern.detector_id == finding.detector_id);
        let (rule_id, action) = matched.map_or((None, RuleAction::Allow), |pattern| {
            (Some(pattern.rule_id.clone()), pattern.action.clone())
        });
        let action = match (action, protocol) {
            (RuleAction::Allow | RuleAction::Detour(_), _) => EnforcementAction::Allow,
            (RuleAction::Deny, Protocol::Http) => {
                EnforcementAction::HttpReject(HttpReject::Forbidden)
            }
            (RuleAction::Deny, Protocol::Tcp) => EnforcementAction::TcpClose(TcpClose {
                mode: TcpCloseMode::Graceful,
            }),
        };
        Decision {
            trace: DecisionTrace {
                policy_generation: self.generation,
                evaluated_stage: PolicyStage::Streaming,
                matched_rule: rule_id,
                match_reasons: vec![MatchReason {
                    criterion: "detector-finding".to_owned(),
                    observed: finding.detector_id.to_string(),
                }],
                final_action: action.kind(),
            },
            action,
        }
    }
}

/// Per-flow matcher retaining only the bytes needed for split-pattern detection.
#[derive(Debug, Clone)]
pub struct StreamScanner {
    program: InspectionProgram,
    direction: Direction,
    carry: Vec<u8>,
    processed_bytes: u64,
}

impl StreamScanner {
    /// Inspects one chunk and reports every newly completed pattern match.
    pub fn inspect(&mut self, bytes: &[u8]) -> Vec<Finding> {
        if bytes.is_empty() || self.program.maximum_pattern_bytes == 0 {
            self.processed_bytes = self
                .processed_bytes
                .saturating_add(usize_as_u64(bytes.len()));
            return Vec::new();
        }
        let carry_len = self.carry.len();
        let mut searchable = Vec::with_capacity(carry_len.saturating_add(bytes.len()));
        searchable.extend_from_slice(&self.carry);
        searchable.extend_from_slice(bytes);
        let base_offset = self.processed_bytes.saturating_sub(usize_as_u64(carry_len));
        let mut findings = Vec::new();
        for pattern in self.program.patterns.iter() {
            if !pattern.applies_to(self.direction) {
                continue;
            }
            for start in match_offsets(&searchable, &pattern.bytes) {
                let end = start.saturating_add(pattern.bytes.len());
                if end <= carry_len {
                    continue;
                }
                findings.push(finding(pattern, self.direction, base_offset, start, end));
            }
        }
        self.processed_bytes = self
            .processed_bytes
            .saturating_add(usize_as_u64(bytes.len()));
        let carry_bytes = self.program.maximum_pattern_bytes.saturating_sub(1);
        let keep_from = searchable.len().saturating_sub(carry_bytes);
        self.carry.clear();
        self.carry.extend_from_slice(&searchable[keep_from..]);
        findings
    }
}

fn match_offsets<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(move |(offset, window)| (window == needle).then_some(offset))
}

fn finding(
    pattern: &InspectionPattern,
    direction: Direction,
    base_offset: u64,
    start: usize,
    end: usize,
) -> Finding {
    Finding {
        detector_id: pattern.detector_id.clone(),
        severity: pattern.severity,
        confidence: pattern.confidence,
        direction,
        byte_range: Some((
            base_offset.saturating_add(usize_as_u64(start)),
            base_offset.saturating_add(usize_as_u64(end)),
        )),
        evidence_hash: EvidenceHash::from_sha256(Sha256::digest(&pattern.bytes).into()),
        tags: pattern.tags.to_vec(),
    }
}

fn usize_as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use freja_domain::{
        Confidence, DetectorId, Direction, EnforcementAction, PolicyGeneration, Protocol, RuleId,
        Severity,
    };

    use crate::{InspectionPattern, InspectionProgram, RuleAction};

    #[test]
    fn pattern_split_across_chunks_produces_one_finding_and_decision() {
        let pattern = InspectionPattern::new(
            DetectorId::new("magic").unwrap(),
            RuleId::new("block-magic").unwrap(),
            b"MALWARE".to_vec(),
            Severity::High,
            Confidence::Confirmed,
            vec![Direction::ClientToUpstream],
            RuleAction::Deny,
            vec!["binary-signature".to_owned()],
        )
        .unwrap();
        let program =
            InspectionProgram::new(PolicyGeneration::new(9).unwrap(), vec![pattern]).unwrap();
        let mut scanner = program.scanner(Direction::ClientToUpstream);

        assert!(scanner.inspect(b"prefix-MAL").is_empty());
        let findings = scanner.inspect(b"WARE-suffix");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].byte_range, Some((7, 14)));
        let decision = program.evaluate(&findings[0], Protocol::Tcp);
        assert!(matches!(decision.action, EnforcementAction::TcpClose(_)));
        assert_eq!(decision.trace.policy_generation.get(), 9);
    }
}
