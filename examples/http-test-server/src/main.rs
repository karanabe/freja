#![forbid(unsafe_code)]
//! Command-line entry point for the local Freja HTTP test origin.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
    net::SocketAddr,
    process::ExitCode,
};

use clap::Parser;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(
    name = "freja-http-test-server",
    about = "Run a local Axum origin for exercising Freja"
)]
struct Arguments {
    /// Address on which the test origin listens.
    #[arg(long, default_value = "127.0.0.1:3001")]
    bind: SocketAddr,

    /// Permit an explicitly selected non-loopback bind address.
    #[arg(long)]
    allow_non_loopback: bool,
}

#[derive(Debug)]
enum AppError {
    NonLoopbackBind(SocketAddr),
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    LocalAddress(io::Error),
    Serve(io::Error),
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLoopbackBind(address) => write!(
                formatter,
                "refusing non-loopback bind address {address}; pass --allow-non-loopback to opt in"
            ),
            Self::Bind { address, source } => {
                write!(
                    formatter,
                    "failed to bind test server to {address}: {source}"
                )
            }
            Self::LocalAddress(source) => {
                write!(
                    formatter,
                    "failed to read bound test-server address: {source}"
                )
            }
            Self::Serve(source) => write!(formatter, "test server failed: {source}"),
        }
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. } | Self::LocalAddress(source) | Self::Serve(source) => {
                Some(source)
            }
            Self::NonLoopbackBind(_) => None,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Arguments::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<(), AppError> {
    if !arguments.bind.ip().is_loopback() && !arguments.allow_non_loopback {
        return Err(AppError::NonLoopbackBind(arguments.bind));
    }

    let listener = TcpListener::bind(arguments.bind)
        .await
        .map_err(|source| AppError::Bind {
            address: arguments.bind,
            source,
        })?;
    let local_address = listener.local_addr().map_err(AppError::LocalAddress)?;
    println!("freja HTTP test server listening on http://{local_address}");
    println!("request headers and bodies are echoed; do not use production secrets");

    axum::serve(listener, freja_http_test_server::app())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(AppError::Serve)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("failed to install Ctrl+C handler: {error}");
    }
}
