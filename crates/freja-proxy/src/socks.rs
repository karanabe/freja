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
const AUTH_SUCCESS: u8 = 0;
const AUTH_FAILURE: u8 = 1;
const SOCKS_COMMAND_CONNECT: u8 = 1;
const SOCKS_RESERVED: u8 = 0;
const ADDRESS_TYPE_IPV4: u8 = 1;
const ADDRESS_TYPE_DOMAIN: u8 = 3;
const ADDRESS_TYPE_IPV6: u8 = 4;

mod protocol;
mod server;
mod session;

pub use protocol::SocksError;
pub use server::Socks5Server;
