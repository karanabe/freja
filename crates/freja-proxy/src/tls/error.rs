use std::{error::Error, fmt, path::PathBuf};

use rustls::pki_types::pem::Error as PemError;

#[derive(Debug, Clone, Copy)]
pub(super) enum TlsInput {
    Certificate,
    PrivateKey,
}

impl fmt::Display for TlsInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => formatter.write_str("CA certificate"),
            Self::PrivateKey => formatter.write_str("CA private key"),
        }
    }
}

/// TLS interception setup or handshake failure.
#[derive(Debug)]
pub enum TlsError {
    /// CA certificate or private-key input could not be read.
    ReadInput {
        /// Stable input category used in diagnostics.
        input: &'static str,
        /// Requested PEM path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
    /// A Unix private-key file was accessible to group or other users.
    InsecurePrivateKeyPermissions {
        /// Insecure private-key path.
        path: PathBuf,
        /// Observed Unix permission bits.
        mode: u32,
    },
    /// The CA private key could not be parsed for certificate issuance.
    CaPrivateKey(rcgen::Error),
    /// The CA certificate was incompatible with certificate issuance.
    CaCertificate(rcgen::Error),
    /// The CA certificate input was not valid PEM.
    CaCertificatePem(PemError),
    /// The certificate input contained no certificate block.
    MissingCaCertificate,
    /// The target host could not be converted to a rustls server name.
    InvalidServerName {
        /// Invalid configured or requested hostname.
        host: String,
    },
    /// Interception negotiated an application protocol outside the supported HTTP set.
    UnsupportedApplicationProtocol {
        /// Negotiated ALPN rendered for diagnostics.
        protocol: String,
    },
    /// Downstream and upstream handshakes selected incompatible protocols.
    ApplicationProtocolMismatch {
        /// Downstream ALPN, if negotiated.
        downstream: Option<String>,
        /// Upstream ALPN, if negotiated.
        upstream: Option<String>,
    },
    /// TLS negotiation with the real upstream failed.
    UpstreamHandshake {
        /// Allowed target hostname.
        host: String,
        /// Underlying handshake I/O error.
        source: std::io::Error,
    },
    /// TLS negotiation with the proxy client failed.
    DownstreamHandshake(std::io::Error),
    /// The downstream handshake exceeded its configured budget.
    DownstreamHandshakeTimedOut,
    /// A per-host leaf certificate could not be generated.
    LeafCertificate(rcgen::Error),
    /// Generated material could not form a rustls server configuration.
    ServerConfiguration(rustls::Error),
    /// A panic poisoned the bounded certificate cache mutex.
    CachePoisoned,
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadInput { input, path, .. } => {
                write!(formatter, "failed to read {input} {}", path.display())
            }
            Self::InsecurePrivateKeyPermissions { path, mode } => write!(
                formatter,
                "CA private key {} has insecure permissions {mode:o}; group and other access must be disabled",
                path.display()
            ),
            Self::CaPrivateKey(_) => formatter.write_str("failed to parse the CA private key"),
            Self::CaCertificate(_) | Self::CaCertificatePem(_) => {
                formatter.write_str("failed to parse the CA certificate")
            }
            Self::MissingCaCertificate => {
                formatter.write_str("CA certificate input contains no certificate")
            }
            Self::InvalidServerName { host } => {
                write!(formatter, "invalid upstream TLS server name {host}")
            }
            Self::UnsupportedApplicationProtocol { protocol } => {
                write!(formatter, "unsupported intercepted TLS ALPN {protocol:?}")
            }
            Self::ApplicationProtocolMismatch {
                downstream,
                upstream,
            } => write!(
                formatter,
                "intercepted TLS ALPN mismatch: downstream {downstream:?}, upstream {upstream:?}"
            ),
            Self::UpstreamHandshake { host, .. } => {
                write!(formatter, "upstream TLS handshake failed for {host}")
            }
            Self::DownstreamHandshake(_) => formatter.write_str("downstream TLS handshake failed"),
            Self::DownstreamHandshakeTimedOut => {
                formatter.write_str("downstream TLS handshake timed out")
            }
            Self::LeafCertificate(_) => {
                formatter.write_str("failed to generate a TLS leaf certificate")
            }
            Self::ServerConfiguration(_) => {
                formatter.write_str("generated TLS server configuration is invalid")
            }
            Self::CachePoisoned => formatter.write_str("TLS leaf cache is unavailable"),
        }
    }
}

impl Error for TlsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ReadInput { source, .. }
            | Self::UpstreamHandshake { source, .. }
            | Self::DownstreamHandshake(source) => Some(source),
            Self::CaCertificatePem(source) => Some(source),
            Self::CaPrivateKey(source)
            | Self::CaCertificate(source)
            | Self::LeafCertificate(source) => Some(source),
            Self::ServerConfiguration(source) => Some(source),
            Self::InsecurePrivateKeyPermissions { .. }
            | Self::MissingCaCertificate
            | Self::InvalidServerName { .. }
            | Self::UnsupportedApplicationProtocol { .. }
            | Self::ApplicationProtocolMismatch { .. }
            | Self::DownstreamHandshakeTimedOut
            | Self::CachePoisoned => None,
        }
    }
}
