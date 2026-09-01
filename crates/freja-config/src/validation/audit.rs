use std::path::PathBuf;

use freja_audit::AuditFailurePolicy;

use crate::{RawAudit, ValidationError};

/// Validated audit sink and redaction settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    /// Validated JSONL destination supplied to bootstrap.
    pub path: PathBuf,
    /// Non-zero audit channel capacity, independent from the UI channel.
    pub channel_capacity: usize,
    /// Explicit traffic behavior when audit delivery cannot proceed.
    pub failure_policy: AuditFailurePolicy,
    /// Lower-case query parameter names whose values are redacted before hashing.
    pub redact_query_parameters: Vec<String>,
    /// Optional Ed25519 signing-seed path for periodic checkpoints.
    pub checkpoint_signing_key: Option<PathBuf>,
    /// Non-zero record interval when checkpoint signing is enabled.
    pub checkpoint_interval: u64,
}

impl TryFrom<RawAudit> for AuditConfig {
    type Error = ValidationError;

    fn try_from(raw: RawAudit) -> Result<Self, Self::Error> {
        if raw.channel_capacity == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "audit.channel_capacity",
            });
        }
        if raw.checkpoint_signing_key.is_some() && raw.checkpoint_interval == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "audit.checkpoint_interval",
            });
        }

        Ok(Self {
            path: raw.path,
            channel_capacity: raw.channel_capacity,
            failure_policy: raw.failure_policy,
            redact_query_parameters: raw
                .redact_query_parameters
                .into_iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
            checkpoint_signing_key: raw.checkpoint_signing_key,
            checkpoint_interval: raw.checkpoint_interval,
        })
    }
}
