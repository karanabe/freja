mod commands;
mod error;

use clap::{Parser, Subcommand};

use crate::error::Result;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Debugging for WebSocket
    #[command(
        name = "websocket",
        visible_alias = "ws",
        about = "Connected or Listen the WebSocket server"
    )]
    Websocket(crate::commands::websocket::WebsocketOpts),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Websocket(opts) => crate::commands::websocket::run(opts).await?,
    }
    Ok(())
}
