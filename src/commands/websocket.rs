use clap::Args;

mod client;
mod server;

use crate::error::Result;
use std::future::Future;

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

pub async fn run_with<FC, FCfut, FS, FSfut>(
    opts: WebsocketOpts,
    client_fn: FC,
    server_fn: FS,
) -> Result<()>
where
    FC: Fn(String, u16) -> FCfut,
    FCfut: Future<Output = Result<()>> + Send,
    FS: Fn(WebsocketOpts) -> FSfut,
    FSfut: Future<Output = Result<()>> + Send,
{
    if opts.listen {
        println!("Listening on {}", opts.url);
        server_fn(opts).await
    } else {
        let port = opts.port;
        let url = opts.url;
        client_fn(url, port).await
    }
}

pub async fn run(opts: WebsocketOpts) -> Result<()> {
    run_with(opts, client::run, server::run).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_client_mode() {
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            opts: WebsocketOpts,
        }
        let wrapper = Wrapper::try_parse_from(["cmd", "example.com", "5555"]).unwrap();
        assert!(!wrapper.opts.listen);
        assert_eq!(wrapper.opts.url, "example.com");
        assert_eq!(wrapper.opts.port, 5555);
    }

    #[test]
    fn parse_server_mode() {
        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            opts: WebsocketOpts,
        }
        let wrapper = Wrapper::try_parse_from(["cmd", "-l", "127.0.0.1", "8888"]).unwrap();
        assert!(wrapper.opts.listen);
        assert_eq!(wrapper.opts.url, "127.0.0.1");
        assert_eq!(wrapper.opts.port, 8888);
    }
}
