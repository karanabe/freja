use std::path::PathBuf;

use freja_domain::TlsHandling;
use freja_policy::HostPattern;

use crate::{RawTls, ValidationError};

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
