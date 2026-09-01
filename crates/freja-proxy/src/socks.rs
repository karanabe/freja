use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any},
    inspection::FlowInspector,
    tcp::relay::{RelayLimits, RelayStats, RelayTermination, relay},
};

const SOCKS_VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const AUTH_NONE: u8 = 0;
const AUTH_USERNAME_PASSWORD: u8 = 2;
const AUTH_UNACCEPTABLE: u8 = 0xff;

mod protocol;
mod server;
mod session;

pub use protocol::SocksError;
pub use server::Socks5Server;
