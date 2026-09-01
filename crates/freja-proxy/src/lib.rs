#![forbid(unsafe_code)]

//! Data-plane engines and isolated networking runtime adapters.

mod destination;
pub mod error;
pub mod event;
pub mod http;
mod inspection;
mod metrics;
#[cfg(feature = "pingora-adapter")]
pub mod pingora;
pub mod runtime;
pub mod settings;
pub mod shutdown;
pub mod socks;
pub mod tcp;
pub mod tls;

pub use error::ProxyError;
pub use event::{DataPlaneEvent, DataPlaneEventSink};
pub use http::HttpForwardServer;
pub use metrics::{DataPlaneMetrics, MetricsSnapshot};
pub use runtime::DataPlaneServices;
pub use settings::{CaptureSettings, ProxyLimits, ProxySettingsError, TlsInterceptionConfig};
pub use shutdown::{ShutdownSender, ShutdownSignal, shutdown_channel};
pub use socks::{Socks5Server, SocksError};
pub use tcp::StaticTcpServer;
pub use tls::{TlsError, TlsInterceptor};
