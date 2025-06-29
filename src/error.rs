use std::{error::Error as StdError, fmt, io, net::AddrParseError, string::FromUtf8Error};
use tokio_tungstenite::tungstenite;

/// Error type shared by all commands
#[derive(Debug)]
pub enum AppError {
    Io(io::Error),
    Ws(tungstenite::Error),
    Addr(AddrParseError),
    Utf8(FromUtf8Error),
    // Add new error here
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "I/O error: {e}"),
            AppError::Ws(e) => write!(f, "WebSocket error: {e}"),
            AppError::Addr(e) => write!(f, "address parse error: {e}"),
            AppError::Utf8(e) => write!(f, "UTF‑8 decode error: {e}"),
        }
    }
}

impl StdError for AppError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            AppError::Io(e) => Some(e),
            AppError::Ws(e) => Some(e),
            AppError::Addr(e) => Some(e),
            AppError::Utf8(e) => Some(e),
        }
    }
}

// Convert error
impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<tungstenite::Error> for AppError {
    fn from(e: tungstenite::Error) -> Self {
        AppError::Ws(e)
    }
}

impl From<AddrParseError> for AppError {
    fn from(e: AddrParseError) -> Self {
        AppError::Addr(e)
    }
}

impl From<FromUtf8Error> for AppError {
    fn from(e: FromUtf8Error) -> Self {
        AppError::Utf8(e)
    }
}

/// Result aliases used throughout the project
pub type Result<T> = std::result::Result<T, AppError>;
