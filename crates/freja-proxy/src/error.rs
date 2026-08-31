use std::{error::Error, fmt, net::SocketAddr};

use freja_audit::PublishError;
use freja_domain::Decision;

/// Concrete data-plane failure with source preservation at I/O boundaries.
#[derive(Debug)]
pub enum ProxyError {
    Bind {
        bind: SocketAddr,
        source: std::io::Error,
    },
    LocalAddress(std::io::Error),
    Accept(std::io::Error),
    Dns {
        host: String,
        source: std::io::Error,
    },
    DnsTimedOut {
        host: String,
    },
    NoResolvedAddresses {
        host: String,
    },
    PolicyDenied {
        decision: Decision,
    },
    DetourLoop {
        decision: Decision,
    },
    ConnectFailed {
        target: SocketAddr,
        source: std::io::Error,
    },
    ConnectTimedOut {
        target: SocketAddr,
    },
    HttpConnection(hyper::Error),
    UpstreamHttp {
        stage: &'static str,
        source: hyper::Error,
    },
    UpstreamResponseTimedOut,
    HttpUpgrade(hyper::Error),
    TunnelRegistration,
    InternalPolicy(freja_domain::IdError),
    RelayRead {
        direction: &'static str,
        source: std::io::Error,
    },
    RelayWrite {
        direction: &'static str,
        source: std::io::Error,
    },
    Audit(PublishError),
    Hook(freja_policy::hook::HookRunError),
    HookMutation(freja_policy::hook::MutationError),
    Interactive(freja_policy::hook::InterceptError),
    InteractiveRejected,
    Socks(crate::socks::SocksError),
    Tls(crate::tls::TlsError),
    ConcurrencyClosed,
    Shutdown,
    Join(tokio::task::JoinError),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { bind, .. } => write!(formatter, "failed to bind TCP listener {bind}"),
            Self::LocalAddress(_) => formatter.write_str("failed to read TCP listener address"),
            Self::Accept(_) => formatter.write_str("failed to accept TCP connection"),
            Self::Dns { host, .. } => write!(formatter, "failed to resolve upstream {host}"),
            Self::DnsTimedOut { host } => {
                write!(formatter, "timed out resolving upstream {host}")
            }
            Self::NoResolvedAddresses { host } => {
                write!(formatter, "DNS returned no addresses for upstream {host}")
            }
            Self::PolicyDenied { decision } => write!(
                formatter,
                "connection denied by policy rule {}",
                decision
                    .trace
                    .matched_rule
                    .as_ref()
                    .map_or("<default>", |rule| rule.as_str())
            ),
            Self::DetourLoop { decision } => write!(
                formatter,
                "TCP detour selected more than once by policy rule {}",
                decision
                    .trace
                    .matched_rule
                    .as_ref()
                    .map_or("<default>", |rule| rule.as_str())
            ),
            Self::ConnectFailed { target, .. } => {
                write!(formatter, "failed to connect to upstream {target}")
            }
            Self::ConnectTimedOut { target } => {
                write!(formatter, "timed out connecting to upstream {target}")
            }
            Self::HttpConnection(_) => formatter.write_str("downstream HTTP/1 connection failed"),
            Self::UpstreamHttp { stage, .. } => {
                write!(formatter, "upstream HTTP/1 {stage} failed")
            }
            Self::UpstreamResponseTimedOut => {
                formatter.write_str("timed out waiting for upstream HTTP response")
            }
            Self::HttpUpgrade(_) => formatter.write_str("CONNECT HTTP upgrade failed"),
            Self::TunnelRegistration => {
                formatter.write_str("CONNECT tunnel registration channel is unavailable")
            }
            Self::InternalPolicy(_) => formatter.write_str("invalid built-in proxy policy rule"),
            Self::RelayRead { direction, .. } => {
                write!(formatter, "failed to read relay direction {direction}")
            }
            Self::RelayWrite { direction, .. } => {
                write!(formatter, "failed to write relay direction {direction}")
            }
            Self::Audit(_) => formatter.write_str("failed to publish a critical audit event"),
            Self::Hook(_) => formatter.write_str("typed hook execution failed"),
            Self::HookMutation(_) => formatter.write_str("typed HTTP hook mutation is invalid"),
            Self::Interactive(_) => formatter.write_str("interactive interception failed"),
            Self::InteractiveRejected => {
                formatter.write_str("flow rejected by interactive interception")
            }
            Self::Socks(_) => formatter.write_str("SOCKS5 session failed"),
            Self::Tls(_) => formatter.write_str("TLS interception failed"),
            Self::ConcurrencyClosed => formatter.write_str("connection concurrency limiter closed"),
            Self::Shutdown => formatter.write_str("proxy session stopped during graceful shutdown"),
            Self::Join(_) => formatter.write_str("TCP session task failed to join"),
        }
    }
}

impl Error for ProxyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. }
            | Self::Dns { source, .. }
            | Self::ConnectFailed { source, .. }
            | Self::RelayRead { source, .. }
            | Self::RelayWrite { source, .. }
            | Self::LocalAddress(source)
            | Self::Accept(source) => Some(source),
            Self::HttpConnection(source)
            | Self::UpstreamHttp { source, .. }
            | Self::HttpUpgrade(source) => Some(source),
            Self::InternalPolicy(source) => Some(source),
            Self::Audit(source) => Some(source),
            Self::Hook(source) => Some(source),
            Self::HookMutation(source) => Some(source),
            Self::Interactive(source) => Some(source),
            Self::Socks(source) => Some(source),
            Self::Tls(source) => Some(source),
            Self::Join(source) => Some(source),
            Self::DnsTimedOut { .. }
            | Self::NoResolvedAddresses { .. }
            | Self::PolicyDenied { .. }
            | Self::DetourLoop { .. }
            | Self::ConnectTimedOut { .. }
            | Self::UpstreamResponseTimedOut
            | Self::TunnelRegistration
            | Self::InteractiveRejected
            | Self::ConcurrencyClosed
            | Self::Shutdown => None,
        }
    }
}
