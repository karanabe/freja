use freja_domain::Port;
use serde::Deserialize;

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

/// A secret-free HTTP proxy credential configuration. Cleartext credentials
/// are never accepted in a configuration file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProxyAuthentication {
    #[serde(default = "default_proxy_realm")]
    pub realm: String,
    pub credential_sha256: String,
}

/// A secret-free SOCKS5 credential configuration. Cleartext credentials are
/// never accepted in a configuration file.
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
