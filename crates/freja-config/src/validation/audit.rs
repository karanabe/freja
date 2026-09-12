use std::{
    num::{NonZeroU64, NonZeroUsize},
    path::{Path, PathBuf},
};

use freja_audit::AuditFailurePolicy;

use crate::{RawAudit, ValidationError};

/// Validated audit sink and redaction settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    path: PathBuf,
    channel_capacity: NonZeroUsize,
    failure_policy: AuditFailurePolicy,
    redact_query_parameters: Vec<String>,
    checkpoint_signing: Option<CheckpointSigningConfig>,
}

impl AuditConfig {
    /// Returns the validated JSONL destination supplied to bootstrap.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the non-zero audit channel capacity.
    pub const fn channel_capacity(&self) -> usize {
        self.channel_capacity.get()
    }

    /// Returns the traffic behavior used when audit delivery cannot proceed.
    pub const fn failure_policy(&self) -> AuditFailurePolicy {
        self.failure_policy
    }

    /// Returns lower-case query parameter names redacted before hashing.
    pub fn redact_query_parameters(&self) -> &[String] {
        &self.redact_query_parameters
    }

    /// Returns periodic checkpoint signing settings when signing is enabled.
    pub const fn checkpoint_signing(&self) -> Option<&CheckpointSigningConfig> {
        self.checkpoint_signing.as_ref()
    }
}

/// Validated periodic checkpoint signing settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSigningConfig {
    key_path: PathBuf,
    interval: NonZeroU64,
}

impl CheckpointSigningConfig {
    /// Returns the permission-protected Ed25519 signing-seed path.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Returns the non-zero interval measured in ordinary audit records.
    pub const fn interval(&self) -> u64 {
        self.interval.get()
    }
}

impl TryFrom<RawAudit> for AuditConfig {
    type Error = ValidationError;

    fn try_from(raw: RawAudit) -> Result<Self, Self::Error> {
        let channel_capacity =
            NonZeroUsize::new(raw.channel_capacity).ok_or(ValidationError::ZeroLimit {
                name: "audit.channel_capacity",
            })?;
        let checkpoint_signing = raw
            .checkpoint_signing_key
            .map(|key_path| {
                let interval =
                    NonZeroU64::new(raw.checkpoint_interval).ok_or(ValidationError::ZeroLimit {
                        name: "audit.checkpoint_interval",
                    })?;
                Ok(CheckpointSigningConfig { key_path, interval })
            })
            .transpose()?;

        Ok(Self {
            path: raw.path,
            channel_capacity,
            failure_policy: raw.failure_policy,
            redact_query_parameters: raw
                .redact_query_parameters
                .into_iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
            checkpoint_signing,
        })
    }
}
