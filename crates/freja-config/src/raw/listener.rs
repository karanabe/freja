use std::fmt;

use freja_domain::Port;
use serde::Deserialize;

/// Raw listener representation with textual endpoints.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RawListener {
    /// HTTP/1 explicit forward-proxy listener.
    HttpForward {
        /// Numeric local socket address.
        bind: String,
        #[serde(default = "default_connect_ports")]
        /// Non-zero destination ports permitted for CONNECT before ACL evaluation.
        connect_ports: Vec<u16>,
        #[serde(default)]
        /// Optional HTTP Basic proxy-authentication requirement.
        authentication: Option<RawProxyAuthentication>,
    },
    /// Static TCP relay from one listener to one upstream.
    TcpStatic {
        /// Numeric local socket address.
        bind: String,
        /// Validated later as a host-and-port upstream endpoint.
        upstream: String,
    },
    /// SOCKS5 CONNECT listener.
    Socks5 {
        /// Numeric local socket address.
        bind: String,
        #[serde(default)]
        /// Optional username/password digest required during negotiation.
        authentication: Option<RawSocksAuthentication>,
    },
}

/// A hashed HTTP proxy credential configuration. Cleartext credentials are
/// never accepted, and debug output redacts the credential-equivalent digest.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawProxyAuthentication {
    #[serde(default = "default_proxy_realm")]
    /// Visible ASCII realm emitted in `Proxy-Authenticate` challenges.
    pub realm: String,
    /// Hex-encoded SHA-256 of the exact `username:password` bytes.
    pub credential_sha256: String,
}

impl fmt::Debug for RawProxyAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawProxyAuthentication")
            .field("realm", &self.realm)
            .field("credential_sha256", &"[REDACTED]")
            .finish()
    }
}

/// A hashed SOCKS5 credential configuration. Cleartext credentials are never
/// accepted, and debug output redacts the credential-equivalent digest.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSocksAuthentication {
    /// Hex-encoded SHA-256 of the exact `username:password` bytes.
    pub credential_sha256: String,
}

impl fmt::Debug for RawSocksAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawSocksAuthentication")
            .field("credential_sha256", &"[REDACTED]")
            .finish()
    }
}

fn default_proxy_realm() -> String {
    "Freja".to_owned()
}

fn default_connect_ports() -> Vec<u16> {
    vec![Port::HTTPS.get()]
}

#[cfg(test)]
mod tests {
    use super::{RawProxyAuthentication, RawSocksAuthentication};

    #[test]
    fn raw_credential_debug_is_redacted() {
        let digest = "credential-equivalent-digest".to_owned();
        let proxy = RawProxyAuthentication {
            realm: "Freja".to_owned(),
            credential_sha256: digest.clone(),
        };
        let socks = RawSocksAuthentication {
            credential_sha256: digest.clone(),
        };

        assert!(!format!("{proxy:?}").contains(&digest));
        assert!(!format!("{socks:?}").contains(&digest));
    }
}
