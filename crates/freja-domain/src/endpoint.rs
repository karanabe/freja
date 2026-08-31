use std::{error::Error, fmt, net::IpAddr, num::NonZeroU16, str::FromStr};

use serde::{Deserialize, Serialize};

/// A validation error for a network endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointError {
    EmptyHost,
    HostTooLong,
    EmptyLabel,
    LabelTooLong { label: String },
    InvalidHostCharacter { character: char },
    InvalidLabelBoundary { label: String },
    ZeroPort,
    MissingPort,
    InvalidPort { value: String },
    InvalidSocketAddress { value: String },
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHost => formatter.write_str("host must not be empty"),
            Self::HostTooLong => formatter.write_str("host must not exceed 253 bytes"),
            Self::EmptyLabel => formatter.write_str("host contains an empty label"),
            Self::LabelTooLong { label } => {
                write!(formatter, "host label {label:?} exceeds 63 bytes")
            }
            Self::InvalidHostCharacter { character } => {
                write!(formatter, "host contains invalid character {character:?}")
            }
            Self::InvalidLabelBoundary { label } => {
                write!(formatter, "host label {label:?} starts or ends with '-'")
            }
            Self::ZeroPort => formatter.write_str("port must be non-zero"),
            Self::MissingPort => formatter.write_str("endpoint is missing a port"),
            Self::InvalidPort { value } => write!(formatter, "invalid port {value:?}"),
            Self::InvalidSocketAddress { value } => {
                write!(formatter, "invalid listen socket address {value:?}")
            }
        }
    }
}

impl Error for EndpointError {}

/// A validated, lower-case ASCII DNS hostname.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HostName(String);

impl HostName {
    /// Validates a hostname. A final DNS root dot is accepted and removed.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when the name is empty, too long, has an
    /// empty/oversized label, or contains characters outside ASCII DNS syntax.
    pub fn new(value: impl Into<String>) -> Result<Self, EndpointError> {
        let value = value.into();
        let normalized = value
            .strip_suffix('.')
            .unwrap_or(&value)
            .to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(EndpointError::EmptyHost);
        }
        if normalized.len() > 253 {
            return Err(EndpointError::HostTooLong);
        }
        for label in normalized.split('.') {
            if label.is_empty() {
                return Err(EndpointError::EmptyLabel);
            }
            if label.len() > 63 {
                return Err(EndpointError::LabelTooLong {
                    label: label.to_owned(),
                });
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(EndpointError::InvalidLabelBoundary {
                    label: label.to_owned(),
                });
            }
            if let Some(character) = label
                .chars()
                .find(|character| !character.is_ascii_alphanumeric() && *character != '-')
            {
                return Err(EndpointError::InvalidHostCharacter { character });
            }
        }
        Ok(Self(normalized))
    }

    /// Returns the normalized hostname.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for HostName {
    type Error = EndpointError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<HostName> for String {
    fn from(value: HostName) -> Self {
        value.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A destination host, preserving whether DNS resolution is required.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TargetHost {
    Ip(IpAddr),
    Name(HostName),
}

impl TargetHost {
    /// Parses an IP literal or validated DNS hostname.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] when a non-IP value is not a valid hostname.
    pub fn parse(value: impl Into<String>) -> Result<Self, EndpointError> {
        let value = value.into();
        let ip_candidate = value
            .strip_prefix('[')
            .and_then(|candidate| candidate.strip_suffix(']'))
            .unwrap_or(&value);
        match ip_candidate.parse::<IpAddr>() {
            Ok(address) => Ok(Self::Ip(address)),
            Err(_) => HostName::new(value).map(Self::Name),
        }
    }

    /// Returns a text representation suitable for DNS lookup or HTTP authority generation.
    pub fn as_host_text(&self) -> String {
        match self {
            Self::Ip(address) => address.to_string(),
            Self::Name(name) => name.as_str().to_owned(),
        }
    }
}

impl fmt::Display for TargetHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(address) => address.fmt(formatter),
            Self::Name(name) => name.fmt(formatter),
        }
    }
}

/// A validated non-zero TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(NonZeroU16);

impl Port {
    /// Conventional HTTPS and CONNECT port.
    pub const HTTPS: Self = match NonZeroU16::new(443) {
        Some(value) => Self(value),
        None => Self(NonZeroU16::MIN),
    };

    /// Creates a non-zero port.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError::ZeroPort`] when `value` is zero.
    pub fn new(value: u16) -> Result<Self, EndpointError> {
        NonZeroU16::new(value)
            .map(Self)
            .ok_or(EndpointError::ZeroPort)
    }

    /// Returns the numeric port.
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for Port {
    type Error = EndpointError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.get()
    }
}

impl fmt::Display for Port {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A local TCP listener endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ListenEndpoint(std::net::SocketAddr);

impl ListenEndpoint {
    /// Creates a listener endpoint.
    pub const fn new(address: std::net::SocketAddr) -> Self {
        Self(address)
    }

    /// Returns the socket address.
    pub const fn address(self) -> std::net::SocketAddr {
        self.0
    }

    /// Reports whether the listener is constrained to a loopback interface.
    pub fn is_loopback(self) -> bool {
        self.0.ip().is_loopback()
    }
}

impl FromStr for ListenEndpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse()
            .map(Self)
            .map_err(|_| EndpointError::InvalidSocketAddress {
                value: value.to_owned(),
            })
    }
}

impl fmt::Display for ListenEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A host and port selected as an upstream target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpstreamEndpoint {
    host: TargetHost,
    port: Port,
}

impl UpstreamEndpoint {
    /// Creates an upstream endpoint from validated components.
    pub const fn new(host: TargetHost, port: Port) -> Self {
        Self { host, port }
    }

    /// Returns the upstream host.
    pub const fn host(&self) -> &TargetHost {
        &self.host
    }

    /// Returns the upstream port.
    pub const fn port(&self) -> Port {
        self.port
    }
}

impl FromStr for UpstreamEndpoint {
    type Err = EndpointError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<std::net::SocketAddr>() {
            return Ok(Self::new(
                TargetHost::Ip(address.ip()),
                Port::new(address.port())?,
            ));
        }
        let (host, port) = value.rsplit_once(':').ok_or(EndpointError::MissingPort)?;
        let port = port
            .parse::<u16>()
            .map_err(|_| EndpointError::InvalidPort {
                value: port.to_owned(),
            })?;
        Ok(Self::new(TargetHost::parse(host)?, Port::new(port)?))
    }
}

impl fmt::Display for UpstreamEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.host() {
            TargetHost::Ip(IpAddr::V6(address)) => write!(formatter, "[{address}]:{}", self.port()),
            host => write!(formatter, "{host}:{}", self.port()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use super::{EndpointError, HostName, TargetHost};

    #[test]
    fn bracketed_ipv6_authority_host_is_accepted() {
        assert_eq!(
            TargetHost::parse("[2001:db8::1]").unwrap(),
            TargetHost::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn exactly_one_dns_root_dot_is_accepted() {
        assert_eq!(
            HostName::new("Example.Test.").unwrap().as_str(),
            "example.test"
        );
        assert_eq!(
            HostName::new("example.test..").unwrap_err(),
            EndpointError::EmptyLabel
        );
    }
}
