#![forbid(unsafe_code)]

//! Typed configuration loading and compilation.

use std::{
    error::Error,
    fmt, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use freja_audit::AuditFailurePolicy;
use freja_domain::{
    Confidence, DetectorId, Direction, EndpointError, HookMode, HttpForwardListener,
    InspectionMode, ListenEndpoint, ListenerSpec, PolicyGeneration, Port, ProxyAuthentication,
    ProxyCredentialHash, RuleId, RuntimeProfile, Severity, Socks5Listener, TcpStaticListener,
    TlsHandling, UiMode, UpstreamEndpoint,
};
use freja_policy::{
    AclPolicy, AclRule, DestinationAccess, DestinationGuard, DestinationGuardSettings, HostPattern,
    InspectionError, InspectionPattern, InspectionProgram, PolicyError, RuleAction,
};
use serde::{Deserialize, Serialize};

/// File loading, TOML decoding, validation, or policy compilation failure.
#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        source: toml::de::Error,
    },
    Validation(ValidationError),
    Policy(PolicyError),
    Inspection(InspectionError),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, .. } => {
                write!(formatter, "failed to read config {}", path.display())
            }
            Self::Parse { .. } => formatter.write_str("failed to parse config as TOML"),
            Self::Validation(error) => write!(formatter, "invalid configuration: {error}"),
            Self::Policy(error) => write!(formatter, "failed to compile policy: {error}"),
            Self::Inspection(error) => {
                write!(formatter, "failed to compile inspection policy: {error}")
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source } => Some(source),
            Self::Validation(source) => Some(source),
            Self::Policy(source) => Some(source),
            Self::Inspection(source) => Some(source),
        }
    }
}

/// A failed cross-field or endpoint invariant.
#[derive(Debug)]
pub enum ValidationError {
    NoListeners,
    InvalidBind {
        value: String,
        source: EndpointError,
    },
    InvalidUpstream {
        value: String,
        source: EndpointError,
    },
    InvalidConnectPort {
        value: u16,
        source: EndpointError,
    },
    EmptyConnectPorts,
    RemoteHttpListenerRequiresAuthentication {
        bind: ListenEndpoint,
    },
    RemoteTcpListenerUnsupported {
        bind: ListenEndpoint,
    },
    RemoteSocksListenerRequiresAuthentication {
        bind: ListenEndpoint,
    },
    InvalidProxyCredentialHash(hex::FromHexError),
    InvalidProxyCredentialHashLength,
    InvalidProxyAuthenticationRealm,
    NonLoopbackBindRequiresOptIn {
        bind: ListenEndpoint,
    },
    InteractiveHooksRequireTui,
    ZeroLimit {
        name: &'static str,
    },
    CapturePrefixExceedsBodyLimit {
        capture_bytes: usize,
        body_prefix_bytes: usize,
    },
    InspectionPatternExceedsBodyLimit {
        detector_id: DetectorId,
        pattern_bytes: usize,
        body_prefix_bytes: usize,
    },
    ZeroPolicyGeneration,
    InvalidPatternHex {
        detector_id: DetectorId,
        source: hex::FromHexError,
    },
    InvalidInspectionPattern(InspectionError),
    TlsInterceptionRequiresCaCertificate,
    TlsInterceptionRequiresCaPrivateKey,
    TlsInterceptionRequiresAllowlist,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoListeners => formatter.write_str("at least one listener is required"),
            Self::InvalidBind { value, .. } => write!(formatter, "invalid listener bind {value:?}"),
            Self::InvalidUpstream { value, .. } => {
                write!(formatter, "invalid static upstream {value:?}")
            }
            Self::InvalidConnectPort { value, .. } => {
                write!(formatter, "invalid CONNECT allowlist port {value}")
            }
            Self::EmptyConnectPorts => {
                formatter.write_str("HTTP listener CONNECT port allowlist must not be empty")
            }
            Self::RemoteHttpListenerRequiresAuthentication { bind } => write!(
                formatter,
                "non-loopback HTTP proxy listener {bind} requires authentication"
            ),
            Self::RemoteTcpListenerUnsupported { bind } => write!(
                formatter,
                "non-loopback static TCP listener {bind} is unsupported because generic TCP has no proxy authentication handshake"
            ),
            Self::RemoteSocksListenerRequiresAuthentication { bind } => write!(
                formatter,
                "non-loopback SOCKS5 listener {bind} requires username/password authentication"
            ),
            Self::InvalidProxyCredentialHash(_) => {
                formatter.write_str("proxy credential hash must be hexadecimal SHA-256")
            }
            Self::InvalidProxyCredentialHashLength => {
                formatter.write_str("proxy credential hash must contain exactly 32 bytes")
            }
            Self::InvalidProxyAuthenticationRealm => {
                formatter.write_str("proxy authentication realm is invalid")
            }
            Self::NonLoopbackBindRequiresOptIn { bind } => write!(
                formatter,
                "listener {bind} is not loopback; set safety.allow_non_loopback = true explicitly"
            ),
            Self::InteractiveHooksRequireTui => {
                formatter.write_str("interactive hooks require runtime.ui = \"tui\"")
            }
            Self::ZeroLimit { name } => write!(formatter, "limit {name} must be non-zero"),
            Self::CapturePrefixExceedsBodyLimit {
                capture_bytes,
                body_prefix_bytes,
            } => write!(
                formatter,
                "capture prefix {capture_bytes} exceeds body-prefix limit {body_prefix_bytes}"
            ),
            Self::InspectionPatternExceedsBodyLimit {
                detector_id,
                pattern_bytes,
                body_prefix_bytes,
            } => write!(
                formatter,
                "detector {detector_id} pattern length {pattern_bytes} exceeds body-prefix limit {body_prefix_bytes}"
            ),
            Self::ZeroPolicyGeneration => formatter.write_str("policy.generation must be non-zero"),
            Self::InvalidPatternHex { detector_id, .. } => {
                write!(
                    formatter,
                    "detector {detector_id} has invalid hexadecimal pattern"
                )
            }
            Self::InvalidInspectionPattern(error) => error.fmt(formatter),
            Self::TlsInterceptionRequiresCaCertificate => {
                formatter.write_str("TLS interception requires tls.ca_certificate")
            }
            Self::TlsInterceptionRequiresCaPrivateKey => {
                formatter.write_str("TLS interception requires tls.ca_private_key")
            }
            Self::TlsInterceptionRequiresAllowlist => {
                formatter.write_str("TLS interception requires a non-empty tls.intercept_hosts")
            }
        }
    }
}

impl Error for ValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidBind { source, .. }
            | Self::InvalidUpstream { source, .. }
            | Self::InvalidConnectPort { source, .. } => Some(source),
            Self::InvalidPatternHex { source, .. } | Self::InvalidProxyCredentialHash(source) => {
                Some(source)
            }
            Self::InvalidInspectionPattern(source) => Some(source),
            _ => None,
        }
    }
}

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

/// Payload capture is disabled by default. Prefix capture remains explicitly bounded.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum RawCapturePolicy {
    #[default]
    MetadataOnly,
    Prefix {
        max_bytes: usize,
    },
}

/// Raw ACL snapshot.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawPolicy {
    pub generation: u64,
    pub default_action: RuleAction,
    pub rules: Vec<AclRule>,
}

/// Raw fixed-pattern detector and finding-policy configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawInspection {
    pub mode: InspectionMode,
    pub patterns: Vec<RawInspectionPattern>,
}

/// One hexadecimal detector signature and its separate policy action.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawInspectionPattern {
    pub detector_id: DetectorId,
    pub rule_id: RuleId,
    pub pattern_hex: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default = "default_inspection_directions")]
    pub directions: Vec<Direction>,
    #[serde(default = "default_inspection_action")]
    pub action: RuleAction,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Opt-in TLS interception inputs. Tunnel mode ignores CA fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawTls {
    pub handling: TlsHandling,
    pub ca_certificate: Option<PathBuf>,
    pub ca_private_key: Option<PathBuf>,
    pub intercept_hosts: Vec<HostPattern>,
    pub leaf_cache_entries: usize,
}

impl Default for RawTls {
    fn default() -> Self {
        Self {
            handling: TlsHandling::Tunnel,
            ca_certificate: None,
            ca_private_key: None,
            intercept_hosts: Vec::new(),
            leaf_cache_entries: 256,
        }
    }
}

const fn default_severity() -> Severity {
    Severity::High
}

const fn default_confidence() -> Confidence {
    Confidence::Confirmed
}

fn default_inspection_directions() -> Vec<Direction> {
    vec![
        Direction::ClientToUpstream,
        Direction::UpstreamToClient,
        Direction::HttpRequestBody,
        Direction::HttpResponseBody,
    ]
}

const fn default_inspection_action() -> RuleAction {
    RuleAction::Deny
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

/// Raw listener representation with textual endpoints.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RawListener {
    HttpForward {
        bind: String,
        #[serde(default = "default_connect_ports")]
        connect_ports: Vec<u16>,
        #[serde(default)]
        authentication: Option<RawProxyAuthentication>,
    },
    TcpStatic {
        bind: String,
        upstream: String,
    },
    Socks5 {
        bind: String,
        #[serde(default)]
        authentication: Option<RawSocksAuthentication>,
    },
}

/// A secret-free proxy credential configuration. The cleartext credential is
/// never accepted in a configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProxyAuthentication {
    #[serde(default = "default_proxy_realm")]
    pub realm: String,
    pub credential_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSocksAuthentication {
    pub credential_sha256: String,
}

fn default_proxy_realm() -> String {
    "Freja".to_owned()
}

fn default_connect_ports() -> Vec<u16> {
    vec![Port::HTTPS.get()]
}

/// Configuration whose external values and cross-field constraints are valid.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    runtime: RuntimeProfile,
    safety: RawSafety,
    limits: Limits,
    audit: AuditConfig,
    capture: CapturePolicy,
    inspection_mode: InspectionMode,
    inspection_patterns: Vec<InspectionPattern>,
    tls: TlsConfig,
    generation: PolicyGeneration,
    destination_guard_settings: DestinationGuardSettings,
    default_action: RuleAction,
    rules: Vec<AclRule>,
    listeners: Vec<ListenerSpec>,
}

impl TryFrom<RawConfig> for ValidatedConfig {
    type Error = ValidationError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        if raw.runtime.hooks == HookMode::Interactive && raw.runtime.ui != UiMode::Tui {
            return Err(ValidationError::InteractiveHooksRequireTui);
        }
        if raw.listeners.is_empty() {
            return Err(ValidationError::NoListeners);
        }
        let limits = Limits::try_from(raw.limits)?;
        let capture = CapturePolicy::try_from((raw.capture, limits.body_prefix_bytes))?;
        let inspection_patterns =
            validate_inspection_patterns(raw.inspection.patterns, limits.body_prefix_bytes)?;
        let tls = validate_tls(raw.tls)?;
        let audit = AuditConfig::try_from(raw.audit)?;
        let generation = PolicyGeneration::new(raw.policy.generation)
            .map_err(|_| ValidationError::ZeroPolicyGeneration)?;
        let destination_guard_settings = DestinationGuardSettings {
            private: raw.safety.private_destinations,
            link_local: raw.safety.link_local_destinations,
            loopback: raw.safety.loopback_destinations,
            metadata: raw.safety.metadata_destinations,
        };
        let mut listeners = Vec::with_capacity(raw.listeners.len());
        for raw_listener in raw.listeners {
            let listener = validate_listener(raw_listener, raw.safety.allow_non_loopback)?;
            listeners.push(listener);
        }
        Ok(Self {
            runtime: raw.runtime,
            safety: raw.safety,
            limits,
            audit,
            capture,
            inspection_mode: raw.inspection.mode,
            inspection_patterns,
            tls,
            generation,
            destination_guard_settings,
            default_action: raw.policy.default_action,
            rules: raw.policy.rules,
            listeners,
        })
    }
}

/// Runtime limits expressed in types and durations rather than raw integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub connections: usize,
    pub header_bytes: usize,
    pub body_prefix_bytes: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub idle_timeout: Duration,
    pub paused_flows: usize,
    pub interception_timeout: Duration,
    pub ui_event_capacity: usize,
}

impl TryFrom<RawLimits> for Limits {
    type Error = ValidationError;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        for (name, value) in [
            ("connections", raw.connections),
            ("header_bytes", raw.header_bytes),
            ("body_prefix_bytes", raw.body_prefix_bytes),
            ("paused_flows", raw.paused_flows),
            ("ui_event_capacity", raw.ui_event_capacity),
        ] {
            if value == 0 {
                return Err(ValidationError::ZeroLimit { name });
            }
        }
        if raw.connect_timeout_ms == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "connect_timeout_ms",
            });
        }
        if raw.read_timeout_ms == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "read_timeout_ms",
            });
        }
        if raw.idle_timeout_ms == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "idle_timeout_ms",
            });
        }
        if raw.interception_timeout_ms == 0 {
            return Err(ValidationError::ZeroLimit {
                name: "interception_timeout_ms",
            });
        }
        Ok(Self {
            connections: raw.connections,
            header_bytes: raw.header_bytes,
            body_prefix_bytes: raw.body_prefix_bytes,
            connect_timeout: Duration::from_millis(raw.connect_timeout_ms),
            read_timeout: Duration::from_millis(raw.read_timeout_ms),
            idle_timeout: Duration::from_millis(raw.idle_timeout_ms),
            paused_flows: raw.paused_flows,
            interception_timeout: Duration::from_millis(raw.interception_timeout_ms),
            ui_event_capacity: raw.ui_event_capacity,
        })
    }
}

/// Validated metadata-only or bounded-prefix capture policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturePolicy {
    MetadataOnly,
    Prefix { max_bytes: usize },
}

/// Validated TLS behavior without optional interception fields in tunnel mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsConfig {
    Tunnel,
    Intercept {
        ca_certificate: PathBuf,
        ca_private_key: PathBuf,
        intercept_hosts: Vec<HostPattern>,
        leaf_cache_entries: usize,
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

/// Validated audit sink and redaction settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub channel_capacity: usize,
    pub failure_policy: AuditFailurePolicy,
    pub redact_query_parameters: Vec<String>,
    pub checkpoint_signing_key: Option<PathBuf>,
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

/// Fully compiled immutable configuration consumed by runtime tasks.
#[derive(Debug, Clone)]
pub struct CompiledConfig {
    runtime: RuntimeProfile,
    safety: RawSafety,
    limits: Limits,
    audit: AuditConfig,
    capture: CapturePolicy,
    inspection_mode: InspectionMode,
    inspection: InspectionProgram,
    tls: TlsConfig,
    listeners: Vec<ListenerSpec>,
    policy: AclPolicy,
    destination_guard: DestinationGuard,
}

impl CompiledConfig {
    /// Loads, validates, and compiles a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file I/O, TOML decoding, validation, or ACL
    /// compilation failures.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        RawConfig::read(path)?.validate()?.compile()
    }

    pub const fn runtime(&self) -> RuntimeProfile {
        self.runtime
    }

    pub const fn safety(&self) -> RawSafety {
        self.safety
    }

    pub const fn limits(&self) -> Limits {
        self.limits
    }

    pub const fn audit(&self) -> &AuditConfig {
        &self.audit
    }

    pub const fn capture(&self) -> CapturePolicy {
        self.capture
    }

    pub const fn inspection_mode(&self) -> InspectionMode {
        self.inspection_mode
    }

    pub const fn inspection(&self) -> &InspectionProgram {
        &self.inspection
    }

    pub const fn tls(&self) -> &TlsConfig {
        &self.tls
    }

    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }

    pub const fn policy(&self) -> &AclPolicy {
        &self.policy
    }

    pub const fn destination_guard(&self) -> &DestinationGuard {
        &self.destination_guard
    }
}

impl ValidatedConfig {
    /// Compiles deterministic policy matchers and freezes the runtime snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Policy`] when an ACL expression is invalid.
    pub fn compile(self) -> Result<CompiledConfig, ConfigError> {
        let policy = AclPolicy::new(self.generation, self.rules, self.default_action)
            .map_err(ConfigError::Policy)?;
        let destination_guard =
            DestinationGuard::new(self.destination_guard_settings).map_err(ConfigError::Policy)?;
        let inspection = InspectionProgram::new(self.generation, self.inspection_patterns)
            .map_err(ConfigError::Inspection)?;
        Ok(CompiledConfig {
            runtime: self.runtime,
            safety: self.safety,
            limits: self.limits,
            audit: self.audit,
            capture: self.capture,
            inspection_mode: self.inspection_mode,
            inspection,
            tls: self.tls,
            listeners: self.listeners,
            policy,
            destination_guard,
        })
    }
}

fn validate_tls(raw: RawTls) -> Result<TlsConfig, ValidationError> {
    match raw.handling {
        TlsHandling::Tunnel => Ok(TlsConfig::Tunnel),
        TlsHandling::Intercept => {
            let ca_certificate = raw
                .ca_certificate
                .ok_or(ValidationError::TlsInterceptionRequiresCaCertificate)?;
            let ca_private_key = raw
                .ca_private_key
                .ok_or(ValidationError::TlsInterceptionRequiresCaPrivateKey)?;
            if raw.intercept_hosts.is_empty() {
                return Err(ValidationError::TlsInterceptionRequiresAllowlist);
            }
            if raw.leaf_cache_entries == 0 {
                return Err(ValidationError::ZeroLimit {
                    name: "tls.leaf_cache_entries",
                });
            }
            Ok(TlsConfig::Intercept {
                ca_certificate,
                ca_private_key,
                intercept_hosts: raw.intercept_hosts,
                leaf_cache_entries: raw.leaf_cache_entries,
            })
        }
    }
}

fn validate_inspection_patterns(
    patterns: Vec<RawInspectionPattern>,
    body_prefix_bytes: usize,
) -> Result<Vec<InspectionPattern>, ValidationError> {
    patterns
        .into_iter()
        .map(|raw| {
            let bytes = hex::decode(&raw.pattern_hex).map_err(|source| {
                ValidationError::InvalidPatternHex {
                    detector_id: raw.detector_id.clone(),
                    source,
                }
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
        })
        .collect()
}

fn validate_listener(
    raw: RawListener,
    allow_non_loopback: bool,
) -> Result<ListenerSpec, ValidationError> {
    match raw {
        RawListener::HttpForward {
            bind,
            connect_ports,
            authentication,
        } => {
            let bind = validate_bind(bind, allow_non_loopback)?;
            if !bind.is_loopback() && authentication.is_none() {
                return Err(ValidationError::RemoteHttpListenerRequiresAuthentication { bind });
            }
            if connect_ports.is_empty() {
                return Err(ValidationError::EmptyConnectPorts);
            }
            let connect_ports = connect_ports
                .into_iter()
                .map(|value| {
                    Port::new(value)
                        .map_err(|source| ValidationError::InvalidConnectPort { value, source })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut listener = HttpForwardListener::with_connect_ports(bind, connect_ports)
                .map_err(|_| ValidationError::EmptyConnectPorts)?;
            if let Some(authentication) = authentication {
                listener =
                    listener.with_authentication(validate_proxy_authentication(authentication)?);
            }
            Ok(ListenerSpec::HttpForward(listener))
        }
        RawListener::TcpStatic { bind, upstream } => {
            let bind = validate_bind(bind, allow_non_loopback)?;
            if !bind.is_loopback() {
                return Err(ValidationError::RemoteTcpListenerUnsupported { bind });
            }
            let value = upstream;
            let upstream = value.parse::<UpstreamEndpoint>().map_err(|source| {
                ValidationError::InvalidUpstream {
                    value: value.clone(),
                    source,
                }
            })?;
            Ok(ListenerSpec::TcpStatic(TcpStaticListener::new(
                bind, upstream,
            )))
        }
        RawListener::Socks5 {
            bind,
            authentication,
        } => {
            let bind = validate_bind(bind, allow_non_loopback)?;
            if !bind.is_loopback() && authentication.is_none() {
                return Err(ValidationError::RemoteSocksListenerRequiresAuthentication { bind });
            }
            let mut listener = Socks5Listener::new(bind);
            if let Some(authentication) = authentication {
                listener = listener.with_authentication(validate_credential_hash(
                    authentication.credential_sha256,
                )?);
            }
            Ok(ListenerSpec::Socks5(listener))
        }
    }
}

fn validate_proxy_authentication(
    raw: RawProxyAuthentication,
) -> Result<ProxyAuthentication, ValidationError> {
    let credential_hash = validate_credential_hash(raw.credential_sha256)?;
    ProxyAuthentication::new(raw.realm, credential_hash)
        .map_err(|_| ValidationError::InvalidProxyAuthenticationRealm)
}

fn validate_credential_hash(value: String) -> Result<ProxyCredentialHash, ValidationError> {
    let decoded = hex::decode(value).map_err(ValidationError::InvalidProxyCredentialHash)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ValidationError::InvalidProxyCredentialHashLength)?;
    Ok(ProxyCredentialHash::new(bytes))
}

fn validate_bind(
    bind_text: String,
    allow_non_loopback: bool,
) -> Result<ListenEndpoint, ValidationError> {
    let bind =
        bind_text
            .parse::<ListenEndpoint>()
            .map_err(|source| ValidationError::InvalidBind {
                value: bind_text,
                source,
            })?;
    if !bind.is_loopback() && !allow_non_loopback {
        return Err(ValidationError::NonLoopbackBindRequiresOptIn { bind });
    }
    Ok(bind)
}

#[cfg(test)]
mod tests {
    use freja_domain::{HookMode, ListenerSpec, UiMode};

    use super::{ConfigError, RawConfig, TlsConfig, ValidationError};

    #[test]
    fn safe_loopback_config_compiles() {
        let raw = RawConfig::parse(
            r#"
                [[listeners]]
                kind = "tcp-static"
                bind = "127.0.0.1:9000"
                upstream = "example.test:9001"
            "#,
        )
        .unwrap();

        let compiled = raw.validate().unwrap().compile().unwrap();
        assert_eq!(compiled.listeners().len(), 1);
        assert_eq!(compiled.runtime().hooks, HookMode::Disabled);
        assert_eq!(compiled.runtime().ui, UiMode::Headless);
        assert!(matches!(compiled.tls(), TlsConfig::Tunnel));
        assert_eq!(compiled.audit().path, std::path::PathBuf::from("."));
    }

    #[test]
    fn non_loopback_listener_requires_explicit_opt_in() {
        let error = RawConfig::parse(
            r#"
                [[listeners]]
                kind = "http-forward"
                bind = "0.0.0.0:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::NonLoopbackBindRequiresOptIn { .. })
        ));
    }

    #[test]
    fn non_loopback_socks_listener_requires_authentication() {
        let error = RawConfig::parse(
            r#"
                [safety]
                allow_non_loopback = true

                [[listeners]]
                kind = "socks5"
                bind = "0.0.0.0:1080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(
                ValidationError::RemoteSocksListenerRequiresAuthentication { .. }
            )
        ));
    }

    #[test]
    fn explicitly_exposed_http_listener_requires_authentication() {
        let error = RawConfig::parse(
            r#"
                [safety]
                allow_non_loopback = true

                [[listeners]]
                kind = "http-forward"
                bind = "0.0.0.0:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(
                ValidationError::RemoteHttpListenerRequiresAuthentication { .. }
            )
        ));
    }

    #[test]
    fn authenticated_non_loopback_http_listener_compiles() {
        let compiled = RawConfig::parse(
            r#"
                [safety]
                allow_non_loopback = true

                [[listeners]]
                kind = "http-forward"
                bind = "0.0.0.0:8080"

                [listeners.authentication]
                realm = "Freja"
                credential_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap()
        .compile()
        .unwrap();

        assert!(matches!(
            compiled.listeners(),
            [ListenerSpec::HttpForward(_)]
        ));
    }

    #[test]
    fn authenticated_non_loopback_socks_listener_compiles() {
        let compiled = RawConfig::parse(
            r#"
                [safety]
                allow_non_loopback = true

                [[listeners]]
                kind = "socks5"
                bind = "0.0.0.0:1080"

                [listeners.authentication]
                credential_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap()
        .compile()
        .unwrap();

        assert!(matches!(compiled.listeners(), [ListenerSpec::Socks5(_)]));
    }

    #[test]
    fn requested_stage_tcp_detour_rule_compiles() {
        let compiled = RawConfig::parse(
            r#"
                [policy]
                generation = 8
                default_action = "allow"

                [[policy.rules]]
                id = "detour-legacy-tcp"
                matcher = { kind = "all", value = [
                  { kind = "protocol", value = "tcp" },
                  { kind = "destination-port", value = { start = 9001, end = 9001 } },
                ] }
                action = { detour = { host = "127.0.0.1", port = 9002 } }

                [[listeners]]
                kind = "tcp-static"
                bind = "127.0.0.1:9000"
                upstream = "127.0.0.1:9001"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap()
        .compile()
        .unwrap();

        assert_eq!(compiled.policy().generation().get(), 8);
    }

    #[test]
    fn interactive_hooks_require_tui() {
        let error = RawConfig::parse(
            r#"
                [runtime]
                hooks = "interactive"

                [[listeners]]
                kind = "http-forward"
                bind = "127.0.0.1:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::InteractiveHooksRequireTui)
        ));
    }

    #[test]
    fn inspection_pattern_must_fit_the_body_prefix_budget() {
        let error = RawConfig::parse(
            r#"
                [limits]
                body_prefix_bytes = 3

                [inspection]

                [[inspection.patterns]]
                detector_id = "oversized"
                rule_id = "deny-oversized"
                pattern_hex = "00010203"

                [[listeners]]
                kind = "http-forward"
                bind = "127.0.0.1:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::InspectionPatternExceedsBodyLimit {
                pattern_bytes: 4,
                body_prefix_bytes: 3,
                ..
            })
        ));
    }

    #[test]
    fn tls_interception_requires_explicit_ca_inputs() {
        let error = RawConfig::parse(
            r#"
                [tls]
                handling = "intercept"

                [[listeners]]
                kind = "http-forward"
                bind = "127.0.0.1:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::TlsInterceptionRequiresCaCertificate)
        ));
    }

    #[test]
    fn tls_interception_requires_a_nonempty_host_allowlist() {
        let error = RawConfig::parse(
            r#"
                [tls]
                handling = "intercept"
                ca_certificate = "ca.pem"
                ca_private_key = "ca-key.pem"

                [[listeners]]
                kind = "http-forward"
                bind = "127.0.0.1:8080"
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            ConfigError::Validation(ValidationError::TlsInterceptionRequiresAllowlist)
        ));
    }
}
