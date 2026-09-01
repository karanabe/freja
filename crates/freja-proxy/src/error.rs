use std::{error::Error, fmt, net::SocketAddr};

use freja_audit::PublishError;
use freja_domain::Decision;

/// Concrete data-plane failure with source preservation at I/O boundaries.
#[derive(Debug)]
pub enum ProxyError {
    /// A TCP listener could not bind its configured address.
    Bind {
        /// Requested local socket address.
        bind: SocketAddr,
        /// Underlying socket error.
        source: std::io::Error,
    },
    /// The operating system could not report a listener's bound address.
    LocalAddress(std::io::Error),
    /// A listener failed while accepting a connection.
    Accept(std::io::Error),
    /// DNS lookup failed for an upstream hostname.
    Dns {
        /// Hostname being resolved.
        host: String,
        /// Resolver I/O error.
        source: std::io::Error,
    },
    /// DNS lookup exceeded the configured connection budget.
    DnsTimedOut {
        /// Hostname being resolved.
        host: String,
    },
    /// DNS completed successfully but returned no candidate address.
    NoResolvedAddresses {
        /// Hostname that produced no answers.
        host: String,
    },
    /// Enforcement rejected the flow before the relevant protocol commitment.
    PolicyDenied {
        /// Rejected action and its explainable trace.
        decision: Decision,
    },
    /// Policy attempted to detour a flow that had already been detoured once.
    DetourLoop {
        /// Second detour decision retained for audit and diagnostics.
        decision: Decision,
    },
    /// A concrete, policy-approved upstream address could not be connected.
    ConnectFailed {
        /// Evaluated destination address.
        target: SocketAddr,
        /// Underlying connection error.
        source: std::io::Error,
    },
    /// An upstream connection attempt exceeded its deadline.
    ConnectTimedOut {
        /// Evaluated destination address.
        target: SocketAddr,
    },
    /// Hyper failed while serving the downstream HTTP/1 connection.
    HttpConnection(hyper::Error),
    /// Hyper failed during an upstream HTTP/1 lifecycle stage.
    UpstreamHttp {
        /// Stable stage name such as handshake or request send.
        stage: &'static str,
        /// Hyper protocol or transport error.
        source: hyper::Error,
    },
    /// No upstream HTTP response arrived before the configured read deadline.
    UpstreamResponseTimedOut,
    /// Hyper could not upgrade a committed CONNECT exchange to a byte tunnel.
    HttpUpgrade(hyper::Error),
    /// The committed CONNECT tunnel could not be registered with its owner task.
    TunnelRegistration,
    /// A built-in proxy rule identity violated domain validation.
    InternalPolicy(freja_domain::IdError),
    /// Reading one relay direction failed.
    RelayRead {
        /// Stable client/upstream direction label.
        direction: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// Writing one relay direction failed.
    RelayWrite {
        /// Stable client/upstream direction label.
        direction: &'static str,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A critical audit event was not accepted under its failure policy.
    Audit(PublishError),
    /// A typed hook failed or exceeded its execution budget.
    Hook(freja_policy::hook::HookRunError),
    /// A typed hook plan violated HTTP framing or memory invariants.
    HookMutation(freja_policy::hook::MutationError),
    /// Interactive interception failed before an operator decision arrived.
    Interactive(freja_policy::hook::InterceptError),
    /// An operator rejected the flow while rejection remained legal.
    InteractiveRejected,
    /// SOCKS5 negotiation, authentication, or request parsing failed.
    Socks(crate::socks::SocksError),
    /// Opt-in TLS interception setup or a handshake failed.
    Tls(crate::tls::TlsError),
    /// The connection semaphore was closed during server lifecycle management.
    ConcurrencyClosed,
    /// Graceful shutdown cancelled an in-flight session.
    Shutdown,
    /// A spawned session task panicked or was cancelled unexpectedly.
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
