use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ListenEndpoint, Port, UpstreamEndpoint};

/// Invalid listener-specific policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerError {
    /// An HTTP listener was configured without any permitted CONNECT port.
    EmptyConnectPorts,
    /// A proxy-authentication realm could not be emitted safely in a challenge.
    InvalidAuthenticationRealm,
}

impl fmt::Display for ListenerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyConnectPorts => {
                formatter.write_str("HTTP listener must allow at least one CONNECT port")
            }
            Self::InvalidAuthenticationRealm => formatter.write_str(
                "proxy authentication realm must be visible ASCII without quotes or backslashes",
            ),
        }
    }
}

/// SHA-256 digest of the exact HTTP Basic `username:password` credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCredentialHash([u8; 32]);

impl ProxyCredentialHash {
    /// Wraps a SHA-256 digest calculated from the exact `username:password` bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the digest without exposing the original credential.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Validated authentication requirement for an explicit proxy listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyAuthentication {
    realm: String,
    credential_hash: ProxyCredentialHash,
}

impl ProxyAuthentication {
    /// Creates a Basic-auth challenge with a pre-hashed credential.
    ///
    /// # Errors
    ///
    /// Returns [`ListenerError::InvalidAuthenticationRealm`] for a realm that
    /// cannot be emitted safely in a quoted HTTP challenge.
    pub fn new(
        realm: impl Into<String>,
        credential_hash: ProxyCredentialHash,
    ) -> Result<Self, ListenerError> {
        let realm = realm.into();
        if realm.is_empty()
            || !realm
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        {
            return Err(ListenerError::InvalidAuthenticationRealm);
        }
        Ok(Self {
            realm,
            credential_hash,
        })
    }

    /// Returns the validated realm emitted in `Proxy-Authenticate`.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Returns the expected credential digest used for constant-time comparison.
    pub const fn credential_hash(&self) -> ProxyCredentialHash {
        self.credential_hash
    }
}

impl Error for ListenerError {}

/// Configuration for an HTTP/1 explicit forward-proxy listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpForwardListener {
    bind: ListenEndpoint,
    connect_ports: BTreeSet<Port>,
    #[serde(default)]
    authentication: Option<ProxyAuthentication>,
}

impl HttpForwardListener {
    /// Creates an HTTP listener.
    pub fn new(bind: ListenEndpoint) -> Self {
        Self {
            bind,
            connect_ports: BTreeSet::from([Port::HTTPS]),
            authentication: None,
        }
    }

    /// Creates an HTTP listener with an explicit non-empty CONNECT port allowlist.
    ///
    /// # Errors
    ///
    /// Returns [`ListenerError::EmptyConnectPorts`] for an empty allowlist.
    pub fn with_connect_ports(
        bind: ListenEndpoint,
        connect_ports: impl IntoIterator<Item = Port>,
    ) -> Result<Self, ListenerError> {
        let connect_ports = connect_ports.into_iter().collect::<BTreeSet<_>>();
        if connect_ports.is_empty() {
            return Err(ListenerError::EmptyConnectPorts);
        }
        Ok(Self {
            bind,
            connect_ports,
            authentication: None,
        })
    }

    /// Adds a validated proxy authentication requirement.
    #[must_use]
    pub fn with_authentication(mut self, authentication: ProxyAuthentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Returns the local bind endpoint.
    pub const fn bind(&self) -> ListenEndpoint {
        self.bind
    }

    /// Reports whether CONNECT may target this port before other ACL evaluation.
    pub fn allows_connect_port(&self, port: Port) -> bool {
        self.connect_ports.contains(&port)
    }

    /// Returns the immutable CONNECT port allowlist.
    pub const fn connect_ports(&self) -> &BTreeSet<Port> {
        &self.connect_ports
    }

    /// Returns the authentication requirement, if this listener has one.
    pub const fn authentication(&self) -> Option<&ProxyAuthentication> {
        self.authentication.as_ref()
    }
}

/// Configuration for a listener that relays TCP to one fixed upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpStaticListener {
    bind: ListenEndpoint,
    upstream: UpstreamEndpoint,
}

/// SOCKS5 listener added after the static-L4 MVP. Authentication is mandatory
/// when configuration exposes it beyond loopback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Listener {
    bind: ListenEndpoint,
    #[serde(default)]
    authentication: Option<ProxyCredentialHash>,
}

impl Socks5Listener {
    /// Creates a SOCKS5 listener without authentication.
    ///
    /// Configuration validation rejects this form for non-loopback binds.
    pub const fn new(bind: ListenEndpoint) -> Self {
        Self {
            bind,
            authentication: None,
        }
    }

    #[must_use]
    /// Adds the credential digest required during SOCKS5 negotiation.
    pub const fn with_authentication(mut self, authentication: ProxyCredentialHash) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Returns the local bind endpoint.
    pub const fn bind(&self) -> ListenEndpoint {
        self.bind
    }

    /// Returns the configured credential digest, if authentication is enabled.
    pub const fn authentication(&self) -> Option<ProxyCredentialHash> {
        self.authentication
    }
}

impl TcpStaticListener {
    /// Creates a static TCP listener.
    pub const fn new(bind: ListenEndpoint, upstream: UpstreamEndpoint) -> Self {
        Self { bind, upstream }
    }

    /// Returns the local bind endpoint.
    pub const fn bind(&self) -> ListenEndpoint {
        self.bind
    }

    /// Returns the fixed upstream.
    pub const fn upstream(&self) -> &UpstreamEndpoint {
        &self.upstream
    }
}

/// A closed set of listener kinds supported by the initial engine boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ListenerSpec {
    /// HTTP/1 explicit forward proxy with CONNECT support.
    HttpForward(HttpForwardListener),
    /// Raw TCP relay to one fixed upstream.
    TcpStatic(TcpStaticListener),
    /// SOCKS5 CONNECT listener.
    Socks5(Socks5Listener),
}

impl ListenerSpec {
    /// Returns the local bind endpoint shared by every listener kind.
    pub const fn bind(&self) -> ListenEndpoint {
        match self {
            Self::HttpForward(listener) => listener.bind(),
            Self::TcpStatic(listener) => listener.bind(),
            Self::Socks5(listener) => listener.bind(),
        }
    }
}
