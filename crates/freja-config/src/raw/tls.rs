use std::path::PathBuf;

use freja_domain::TlsHandling;
use freja_policy::HostPattern;
use serde::Deserialize;

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
