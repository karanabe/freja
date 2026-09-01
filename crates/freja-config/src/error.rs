use std::{error::Error, fmt, path::PathBuf};

use freja_domain::{DetectorId, EndpointError, ListenEndpoint};
use freja_policy::{InspectionError, PolicyError};

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
