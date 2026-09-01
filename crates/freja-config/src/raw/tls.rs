use std::path::PathBuf;

use freja_domain::TlsHandling;
use freja_policy::HostPattern;
use serde::Deserialize;

/// Opt-in TLS interception inputs. Tunnel mode ignores CA fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RawTls {
    /// Tunnel by default, or explicitly opt in to TLS interception.
    pub handling: TlsHandling,
    /// PEM CA certificate used to issue per-host leaf certificates.
    pub ca_certificate: Option<PathBuf>,
    /// PEM CA private key; filesystem permissions are checked at runtime loading.
    pub ca_private_key: Option<PathBuf>,
    /// Exact or suffix hostname patterns eligible for interception.
    pub intercept_hosts: Vec<HostPattern>,
    /// Maximum generated leaf certificates retained in memory.
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
