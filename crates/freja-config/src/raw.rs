mod inspection;
mod listener;
mod tls;

use std::{fs, path::Path, path::PathBuf};

use freja_audit::AuditFailurePolicy;
use freja_domain::RuntimeProfile;
use freja_policy::{AclRule, DestinationAccess, RuleAction};
use serde::Deserialize;

pub use self::{
    inspection::{RawCapturePolicy, RawInspection, RawInspectionPattern},
    listener::{RawListener, RawProxyAuthentication, RawSocksAuthentication},
    tls::RawTls,
};

use crate::{ConfigError, ValidatedConfig};

/// Direct TOML representation. It must be validated before runtime use.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawConfig {
    pub runtime: RuntimeProfile,
    pub safety: RawSafety,
    pub limits: RawLimits,
    pub audit: RawAudit,
    pub capture: RawCapturePolicy,
    pub inspection: RawInspection,
    pub tls: RawTls,
    pub policy: RawPolicy,
    pub listeners: Vec<RawListener>,
}

impl RawConfig {
    /// Parses untrusted TOML text without assuming semantic validity.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Parse`] when `input` is not valid Freja TOML.
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        toml::from_str(input).map_err(|source| ConfigError::Parse { source })
    }

    /// Reads and parses a raw configuration file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the file cannot be read or decoded.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let input = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&input)
    }

    /// Validates cross-field and endpoint invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when an endpoint, resource limit,
    /// capture bound, or runtime mode combination is unsafe or invalid.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        ValidatedConfig::try_from(self).map_err(ConfigError::Validation)
    }
}

/// Explicitly risky listener exposure options.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawSafety {
    pub allow_non_loopback: bool,
    pub private_destinations: DestinationAccess,
    pub link_local_destinations: DestinationAccess,
    pub loopback_destinations: DestinationAccess,
    pub metadata_destinations: DestinationAccess,
}

/// Resource and time limits enforced by network and interception layers.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawLimits {
    pub connections: usize,
    pub header_bytes: usize,
    pub body_prefix_bytes: usize,
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub paused_flows: usize,
    pub interception_timeout_ms: u64,
    pub ui_event_capacity: usize,
}

impl Default for RawLimits {
    fn default() -> Self {
        Self {
            connections: 1_024,
            header_bytes: 64 * 1_024,
            body_prefix_bytes: 64 * 1_024,
            connect_timeout_ms: 10_000,
            read_timeout_ms: 30_000,
            idle_timeout_ms: 60_000,
            paused_flows: 16,
            interception_timeout_ms: 30_000,
            ui_event_capacity: 1_024,
        }
    }
}

/// Audit delivery configuration. Audit and UI publishers are intentionally separate.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawAudit {
    pub path: PathBuf,
    pub channel_capacity: usize,
    pub failure_policy: AuditFailurePolicy,
    pub redact_query_parameters: Vec<String>,
    pub checkpoint_signing_key: Option<PathBuf>,
    pub checkpoint_interval: u64,
}

impl Default for RawAudit {
    fn default() -> Self {
        Self {
            path: PathBuf::from("."),
            channel_capacity: 1_024,
            failure_policy: AuditFailurePolicy::FailClosed,
            redact_query_parameters: vec![
                "access_token".to_owned(),
                "api_key".to_owned(),
                "password".to_owned(),
                "secret".to_owned(),
                "token".to_owned(),
            ],
            checkpoint_signing_key: None,
            checkpoint_interval: 1_000,
        }
    }
}

/// Raw ACL snapshot.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawPolicy {
    pub generation: u64,
    pub default_action: RuleAction,
    pub rules: Vec<AclRule>,
}

impl Default for RawPolicy {
    fn default() -> Self {
        Self {
            generation: 1,
            default_action: RuleAction::Allow,
            rules: Vec::new(),
        }
    }
}
