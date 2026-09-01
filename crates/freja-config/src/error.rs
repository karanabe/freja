use std::{error::Error, fmt, path::PathBuf};

use freja_domain::{DetectorId, EndpointError, ListenEndpoint};
use freja_policy::{InspectionError, PolicyError};

/// File loading, TOML decoding, validation, or policy compilation failure.
#[derive(Debug)]
pub enum ConfigError {
    /// The configuration file could not be read.
    Read {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// Input was not valid Freja TOML.
    Parse {
        /// TOML syntax or data-model error.
        source: toml::de::Error,
    },
    /// Parsed values violated a local or cross-field invariant.
    Validation(ValidationError),
    /// ACL or destination policy compilation failed.
    Policy(PolicyError),
    /// Inspection pattern compilation failed.
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
    /// No listener was configured, so the data plane could not accept traffic.
    NoListeners,
    /// A listener bind string was not a valid numeric socket address.
    InvalidBind {
        /// Unparseable configured value.
        value: String,
        /// Endpoint validation error.
        source: EndpointError,
    },
    /// A static upstream string was not a valid host-and-port endpoint.
    InvalidUpstream {
        /// Unparseable configured value.
        value: String,
        /// Endpoint validation error.
        source: EndpointError,
    },
    /// A CONNECT allowlist contained port zero or another invalid value.
    InvalidConnectPort {
        /// Invalid numeric port.
        value: u16,
        /// Port validation error.
        source: EndpointError,
    },
    /// A forward-proxy listener had no CONNECT ports, which would make its policy ambiguous.
    EmptyConnectPorts,
    /// A non-loopback HTTP proxy was configured without authentication.
    RemoteHttpListenerRequiresAuthentication {
        /// Exposed listener endpoint.
        bind: ListenEndpoint,
    },
    /// A static TCP listener was exposed remotely despite having no authentication handshake.
    RemoteTcpListenerUnsupported {
        /// Exposed listener endpoint.
        bind: ListenEndpoint,
    },
    /// A non-loopback SOCKS5 proxy was configured without authentication.
    RemoteSocksListenerRequiresAuthentication {
        /// Exposed listener endpoint.
        bind: ListenEndpoint,
    },
    /// A proxy credential digest was not hexadecimal.
    InvalidProxyCredentialHash(hex::FromHexError),
    /// A decoded proxy credential digest was not exactly one SHA-256 value.
    InvalidProxyCredentialHashLength,
    /// An HTTP authentication realm could not be safely quoted in a challenge.
    InvalidProxyAuthenticationRealm,
    /// A non-loopback listener was configured without the explicit safety opt-in.
    NonLoopbackBindRequiresOptIn {
        /// Listener endpoint requiring the opt-in.
        bind: ListenEndpoint,
    },
    /// Interactive hooks were selected without the TUI that supplies decisions.
    InteractiveHooksRequireTui,
    /// A resource bound or timeout was zero.
    ZeroLimit {
        /// Stable configuration field name used in diagnostics.
        name: &'static str,
    },
    /// Raw payload capture exceeded the maximum inspected body prefix.
    CapturePrefixExceedsBodyLimit {
        /// Requested raw capture length in bytes.
        capture_bytes: usize,
        /// Maximum retained body prefix in bytes.
        body_prefix_bytes: usize,
    },
    /// A detector signature could never fit within the inspection window.
    InspectionPatternExceedsBodyLimit {
        /// Detector owning the oversized pattern.
        detector_id: DetectorId,
        /// Decoded pattern length in bytes.
        pattern_bytes: usize,
        /// Maximum inspected prefix length in bytes.
        body_prefix_bytes: usize,
    },
    /// Policy generation zero was supplied even though zero is reserved.
    ZeroPolicyGeneration,
    /// A detector signature was not valid hexadecimal.
    InvalidPatternHex {
        /// Detector owning the invalid pattern.
        detector_id: DetectorId,
        /// Hexadecimal decoder error.
        source: hex::FromHexError,
    },
    /// A decoded detector definition violated inspection invariants.
    InvalidInspectionPattern(InspectionError),
    /// Interception was enabled without a CA certificate path.
    TlsInterceptionRequiresCaCertificate,
    /// Interception was enabled without a CA private-key path.
    TlsInterceptionRequiresCaPrivateKey,
    /// Interception was enabled without an explicit hostname allowlist.
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
