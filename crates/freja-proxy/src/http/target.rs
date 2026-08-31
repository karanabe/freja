use std::{error::Error, fmt};

use freja_domain::{EndpointError, Port, TargetHost};
use http::Uri;

/// Parsed absolute-form or CONNECT authority-form destination.
#[derive(Debug, Clone)]
pub(super) struct ForwardTarget {
    host: TargetHost,
    port: Port,
    authority: String,
    origin_uri: Option<Uri>,
}

impl ForwardTarget {
    /// Parses an `http` absolute-form request target.
    pub(super) fn from_absolute(uri: &Uri) -> Result<Self, TargetError> {
        if uri.scheme_str() != Some("http") {
            return Err(TargetError::UnsupportedScheme);
        }
        let authority = uri.authority().ok_or(TargetError::MissingAuthority)?;
        reject_userinfo(authority.as_str())?;
        let host = TargetHost::parse(authority.host()).map_err(TargetError::Endpoint)?;
        let port = match authority.port_u16() {
            Some(port) => Port::new(port).map_err(TargetError::Endpoint)?,
            None => Port::new(80).map_err(TargetError::Endpoint)?,
        };
        let path_and_query = uri.path_and_query().map_or("/", |value| value.as_str());
        let origin_uri = path_and_query
            .parse::<Uri>()
            .map_err(TargetError::OriginUri)?;
        Ok(Self {
            host,
            port,
            authority: authority.as_str().to_owned(),
            origin_uri: Some(origin_uri),
        })
    }

    /// Parses CONNECT authority-form and requires an explicit port.
    pub(super) fn from_connect(uri: &Uri) -> Result<Self, TargetError> {
        if uri.scheme().is_some() {
            return Err(TargetError::ConnectNotAuthorityForm);
        }
        let authority = uri.authority().ok_or(TargetError::MissingAuthority)?;
        reject_userinfo(authority.as_str())?;
        let port = authority
            .port_u16()
            .ok_or(TargetError::MissingConnectPort)?;
        Ok(Self {
            host: TargetHost::parse(authority.host()).map_err(TargetError::Endpoint)?,
            port: Port::new(port).map_err(TargetError::Endpoint)?,
            authority: authority.as_str().to_owned(),
            origin_uri: None,
        })
    }

    pub(super) const fn host(&self) -> &TargetHost {
        &self.host
    }

    pub(super) const fn port(&self) -> Port {
        self.port
    }

    pub(super) fn authority(&self) -> &str {
        &self.authority
    }

    pub(super) fn origin_uri(&self) -> Option<&Uri> {
        self.origin_uri.as_ref()
    }
}

/// Invalid or unsupported explicit-proxy request target.
#[derive(Debug)]
pub(super) enum TargetError {
    UnsupportedScheme,
    MissingAuthority,
    UserInfoNotAllowed,
    ConnectNotAuthorityForm,
    MissingConnectPort,
    Endpoint(EndpointError),
    OriginUri(http::uri::InvalidUri),
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedScheme => {
                formatter.write_str("plain forwarding requires an http absolute-form target")
            }
            Self::MissingAuthority => formatter.write_str("request target has no authority"),
            Self::UserInfoNotAllowed => {
                formatter.write_str("request-target user information is not allowed")
            }
            Self::ConnectNotAuthorityForm => {
                formatter.write_str("CONNECT target must use authority-form")
            }
            Self::MissingConnectPort => {
                formatter.write_str("CONNECT authority must include an explicit port")
            }
            Self::Endpoint(_) => formatter.write_str("request target contains an invalid endpoint"),
            Self::OriginUri(_) => formatter.write_str("request target has an invalid path/query"),
        }
    }
}

impl Error for TargetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Endpoint(source) => Some(source),
            Self::OriginUri(source) => Some(source),
            Self::UnsupportedScheme
            | Self::MissingAuthority
            | Self::UserInfoNotAllowed
            | Self::ConnectNotAuthorityForm
            | Self::MissingConnectPort => None,
        }
    }
}

fn reject_userinfo(authority: &str) -> Result<(), TargetError> {
    if authority.contains('@') {
        return Err(TargetError::UserInfoNotAllowed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv6Addr};

    use freja_domain::TargetHost;

    use super::ForwardTarget;

    #[test]
    fn absolute_and_connect_targets_accept_bracketed_ipv6() {
        let absolute =
            ForwardTarget::from_absolute(&"http://[2001:db8::1]:8080/path".parse().unwrap())
                .unwrap();
        let connect = ForwardTarget::from_connect(&"[2001:db8::1]:443".parse().unwrap()).unwrap();
        let expected = TargetHost::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));

        assert_eq!(absolute.host(), &expected);
        assert_eq!(connect.host(), &expected);
    }
}
