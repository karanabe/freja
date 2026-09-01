use std::path::PathBuf;

use freja_domain::TlsHandling;
use freja_policy::HostPattern;

use crate::{RawTls, ValidationError};

/// Validated TLS behavior without optional interception fields in tunnel mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsConfig {
    /// Preserve end-to-end TLS and relay opaque encrypted bytes.
    Tunnel,
    /// Terminate TLS for explicitly allowed hostnames using operator-owned CA material.
    Intercept {
        /// PEM CA certificate path.
        ca_certificate: PathBuf,
        /// PEM CA private-key path.
        ca_private_key: PathBuf,
        /// Non-empty set of host patterns eligible for interception.
        intercept_hosts: Vec<HostPattern>,
        /// Non-zero in-memory leaf-certificate cache capacity.
        leaf_cache_entries: usize,
    },
}

pub(super) fn validate(raw: RawTls) -> Result<TlsConfig, ValidationError> {
    match raw.handling {
        TlsHandling::Tunnel => Ok(TlsConfig::Tunnel),
        TlsHandling::Intercept => validate_interception(raw),
    }
}

fn validate_interception(raw: RawTls) -> Result<TlsConfig, ValidationError> {
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
