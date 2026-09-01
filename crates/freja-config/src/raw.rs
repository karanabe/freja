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
    /// Independent UI, enforcement, and hook selections.
    pub runtime: RuntimeProfile,
    /// Explicit opt-ins for listener exposure and protected destination classes.
    pub safety: RawSafety,
    /// Unvalidated resource and timeout bounds.
    pub limits: RawLimits,
    /// Audit destination, delivery, redaction, and checkpoint settings.
    pub audit: RawAudit,
    /// Payload capture selection; defaults to metadata only.
    pub capture: RawCapturePolicy,
    /// Inspection execution mode and detector definitions.
    pub inspection: RawInspection,
    /// Tunnel or opt-in interception settings.
    pub tls: RawTls,
    /// Ordered ACL snapshot and generation.
    pub policy: RawPolicy,
    /// Listener declarations; validation requires at least one.
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
    /// Whether configuration may expose authenticated listeners beyond loopback.
    pub allow_non_loopback: bool,
    /// Access policy for RFC 1918 and equivalent private addresses.
    pub private_destinations: DestinationAccess,
    /// Access policy for link-local destinations.
    pub link_local_destinations: DestinationAccess,
    /// Access policy for loopback destinations.
    pub loopback_destinations: DestinationAccess,
    /// Access policy for known cloud metadata-service destinations.
    pub metadata_destinations: DestinationAccess,
}

/// Resource and time limits enforced by network and interception layers.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawLimits {
    /// Maximum concurrently admitted flows.
    pub connections: usize,
    /// Maximum HTTP header bytes accepted for one message head.
    pub header_bytes: usize,
    /// Maximum bytes retained for inspection from one body or direction.
    pub body_prefix_bytes: usize,
    /// Upstream connection deadline in milliseconds.
    pub connect_timeout_ms: u64,
    /// Individual network read deadline in milliseconds.
    pub read_timeout_ms: u64,
    /// Maximum duration without flow progress in milliseconds.
    pub idle_timeout_ms: u64,
    /// Maximum flows simultaneously paused for interactive interception.
    pub paused_flows: usize,
    /// Operator decision deadline in milliseconds.
    pub interception_timeout_ms: u64,
    /// Bounded best-effort UI event channel capacity.
    pub ui_event_capacity: usize,
    /// Maximum payload bytes retained for one TUI traffic side.
    pub ui_content_bytes: usize,
    /// Maximum HTTP transactions or TCP sessions retained by the TUI.
    pub ui_retained_rows: usize,
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
            ui_content_bytes: 64 * 1_024,
            ui_retained_rows: 128,
        }
    }
}

/// Audit delivery configuration. Audit and UI publishers are intentionally separate.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawAudit {
    /// JSONL output path, or directory interpreted by bootstrap policy.
    pub path: PathBuf,
    /// Capacity of the audit-only bounded channel.
    pub channel_capacity: usize,
    /// Whether saturation blocks traffic or returns an explicit delivery failure.
    pub failure_policy: AuditFailurePolicy,
    /// Case-insensitive query parameter names whose values must be redacted.
    pub redact_query_parameters: Vec<String>,
    /// Optional path to a hex-encoded Ed25519 signing seed.
    pub checkpoint_signing_key: Option<PathBuf>,
    /// Number of ordinary records between signed checkpoints.
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
    /// Non-zero identity embedded in every compiled decision trace.
    pub generation: u64,
    /// Action selected when no rule matches.
    pub default_action: RuleAction,
    /// ACL rules evaluated in declaration order.
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
