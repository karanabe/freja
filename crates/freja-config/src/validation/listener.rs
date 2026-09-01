use freja_domain::{
    HttpForwardListener, ListenEndpoint, ListenerSpec, Port, ProxyAuthentication,
    ProxyCredentialHash, Socks5Listener, TcpStaticListener, UpstreamEndpoint,
};

use crate::{RawListener, RawProxyAuthentication, RawSocksAuthentication, ValidationError};

pub(super) fn validate_all(
    raw_listeners: Vec<RawListener>,
    allow_non_loopback: bool,
) -> Result<Vec<ListenerSpec>, ValidationError> {
    raw_listeners
        .into_iter()
        .map(|listener| validate(listener, allow_non_loopback))
        .collect()
}

fn validate(raw: RawListener, allow_non_loopback: bool) -> Result<ListenerSpec, ValidationError> {
    match raw {
        RawListener::HttpForward {
            bind,
            connect_ports,
            authentication,
        } => validate_http_forward(bind, connect_ports, authentication, allow_non_loopback),
        RawListener::TcpStatic { bind, upstream } => {
            validate_tcp_static(bind, upstream, allow_non_loopback)
        }
        RawListener::Socks5 {
            bind,
            authentication,
        } => validate_socks5(bind, authentication, allow_non_loopback),
    }
}

fn validate_http_forward(
    bind: String,
    connect_ports: Vec<u16>,
    authentication: Option<RawProxyAuthentication>,
    allow_non_loopback: bool,
) -> Result<ListenerSpec, ValidationError> {
    let bind = validate_bind(bind, allow_non_loopback)?;
    if !bind.is_loopback() && authentication.is_none() {
        return Err(ValidationError::RemoteHttpListenerRequiresAuthentication { bind });
    }
    if connect_ports.is_empty() {
        return Err(ValidationError::EmptyConnectPorts);
    }

    let connect_ports = connect_ports
        .into_iter()
        .map(|value| {
            Port::new(value).map_err(|source| ValidationError::InvalidConnectPort { value, source })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut listener = HttpForwardListener::with_connect_ports(bind, connect_ports)
        .map_err(|_| ValidationError::EmptyConnectPorts)?;
    if let Some(authentication) = authentication {
        listener = listener.with_authentication(validate_proxy_authentication(authentication)?);
    }
    Ok(ListenerSpec::HttpForward(listener))
}

fn validate_tcp_static(
    bind: String,
    upstream: String,
    allow_non_loopback: bool,
) -> Result<ListenerSpec, ValidationError> {
    let bind = validate_bind(bind, allow_non_loopback)?;
    if !bind.is_loopback() {
        return Err(ValidationError::RemoteTcpListenerUnsupported { bind });
    }
    let upstream = upstream.parse::<UpstreamEndpoint>().map_err(|source| {
        ValidationError::InvalidUpstream {
            value: upstream,
            source,
        }
    })?;
    Ok(ListenerSpec::TcpStatic(TcpStaticListener::new(
        bind, upstream,
    )))
}

fn validate_socks5(
    bind: String,
    authentication: Option<RawSocksAuthentication>,
    allow_non_loopback: bool,
) -> Result<ListenerSpec, ValidationError> {
    let bind = validate_bind(bind, allow_non_loopback)?;
    if !bind.is_loopback() && authentication.is_none() {
        return Err(ValidationError::RemoteSocksListenerRequiresAuthentication { bind });
    }

    let mut listener = Socks5Listener::new(bind);
    if let Some(authentication) = authentication {
        listener = listener
            .with_authentication(validate_credential_hash(authentication.credential_sha256)?);
    }
    Ok(ListenerSpec::Socks5(listener))
}

fn validate_proxy_authentication(
    raw: RawProxyAuthentication,
) -> Result<ProxyAuthentication, ValidationError> {
    let credential_hash = validate_credential_hash(raw.credential_sha256)?;
    ProxyAuthentication::new(raw.realm, credential_hash)
        .map_err(|_| ValidationError::InvalidProxyAuthenticationRealm)
}

fn validate_credential_hash(value: String) -> Result<ProxyCredentialHash, ValidationError> {
    let decoded = hex::decode(value).map_err(ValidationError::InvalidProxyCredentialHash)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ValidationError::InvalidProxyCredentialHashLength)?;
    Ok(ProxyCredentialHash::new(bytes))
}

fn validate_bind(
    bind_text: String,
    allow_non_loopback: bool,
) -> Result<ListenEndpoint, ValidationError> {
    let bind =
        bind_text
            .parse::<ListenEndpoint>()
            .map_err(|source| ValidationError::InvalidBind {
                value: bind_text,
                source,
            })?;
    if !bind.is_loopback() && !allow_non_loopback {
        return Err(ValidationError::NonLoopbackBindRequiresOptIn { bind });
    }
    Ok(bind)
}
