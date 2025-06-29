use clap::Args;

mod client;
mod server;

use crate::error::Result;

/// Sub command for `freja ws`
#[derive(Args, Debug)]
pub struct WebsocketOpts {
    /// Server mode (`-l` listen)
    #[arg(short, long, help = "Start in server mode")]
    pub listen: bool,

    /// Host name or address to connect to
    #[arg(value_name = "URL", help = "Host name or IP address")]
    pub url: String,

    /// Port to connect to (used only in client mode)
    #[arg(value_name = "PORT", help = "Port number", default_value_t = 4444)]
    pub port: u16,
}

pub async fn run(opts: WebsocketOpts) -> Result<()> {
    if opts.listen {
        println!("Listening on {}", opts.url);
        server::run(opts).await
    } else {
        let port = opts.port;
        let url = opts.url;
        client::run(url, port).await
    }
}
