#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Data-plane engines and isolated networking runtime adapters.

mod destination;
/// Concrete data-plane errors with preserved I/O and policy sources.
pub mod error;
/// Immutable best-effort observer events, separate from critical audit delivery.
pub mod event;
/// Hyper-based HTTP/1 explicit forward-proxy engine and CONNECT tunneling.
pub mod http;
mod inspection;
mod metrics;
#[cfg(feature = "pingora-adapter")]
/// Optional Pingora 0.8.1 `ServerApp` transport boundary.
pub mod pingora;
/// Shared data-plane services and immutable runtime snapshots.
pub mod runtime;
/// Validated resource, capture, and TLS interception inputs.
pub mod settings;
/// Cloneable graceful-shutdown signaling.
pub mod shutdown;
/// SOCKS5 CONNECT protocol and listener implementation.
pub mod socks;
/// Static listener-to-upstream TCP relay.
pub mod tcp;
/// Opt-in TLS interception and bounded certificate caching.
pub mod tls;

pub use error::ProxyError;
pub use event::{DataPlaneEvent, DataPlaneEventSink};
pub use http::HttpForwardServer;
pub use metrics::{DataPlaneMetrics, MetricsSnapshot};
pub use runtime::DataPlaneServices;
pub use settings::{
    CaptureSettings, ProxyLimits, ProxySettingsError, TlsInterceptionConfig, UiCaptureSettings,
};
pub use shutdown::{ShutdownSender, ShutdownSignal, shutdown_channel};
pub use socks::{Socks5Server, SocksError};
pub use tcp::StaticTcpServer;
pub use tls::{TlsError, TlsInterceptor};
