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
    ReadInput {
        input: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    InsecurePrivateKeyPermissions {
        path: PathBuf,
        mode: u32,
    },
    CaPrivateKey(rcgen::Error),
    CaCertificate(rcgen::Error),
    CaCertificatePem(PemError),
    MissingCaCertificate,
    InvalidServerName {
        host: String,
    },
    UnsupportedApplicationProtocol {
        protocol: String,
    },
    ApplicationProtocolMismatch {
        downstream: Option<String>,
        upstream: Option<String>,
    },
    UpstreamHandshake {
        host: String,
        source: std::io::Error,
    },
    DownstreamHandshake(std::io::Error),
    DownstreamHandshakeTimedOut,
    LeafCertificate(rcgen::Error),
    ServerConfiguration(rustls::Error),
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
