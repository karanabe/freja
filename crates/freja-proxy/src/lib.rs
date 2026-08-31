#![forbid(unsafe_code)]

//! Network engine boundary and runtime adapters.

mod destination;
pub mod engine;
pub mod error;
pub mod http;
mod inspection;
mod metrics;
#[cfg(feature = "pingora-adapter")]
pub mod pingora;
pub mod runtime;
pub mod shutdown;
pub mod socks;
pub mod tcp;
pub mod tls;

pub use engine::{EngineKind, ListenerEngine};
pub use error::ProxyError;
pub use http::HttpForwardServer;
pub use metrics::{DataPlaneMetrics, MetricsSnapshot};
pub use runtime::DataPlaneServices;
pub use shutdown::{ShutdownSender, ShutdownSignal, shutdown_channel};
pub use socks::{Socks5Server, SocksError};
pub use tcp::StaticTcpServer;
pub use tls::{TlsError, TlsInterceptor};
