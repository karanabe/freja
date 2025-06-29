use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::error::Result;

/// Build a websocket URL from host and port
pub fn url_from_host(host: &str, port: u16) -> String {
    format!("ws://{}:{}/", host, port)
}

pub async fn run(host: String, port: u16) -> Result<()> {
    let url = url_from_host(&host, port);
    println!("Connecting to {url}");

    let (ws, _) = connect_async(&url).await?;
    let (mut ws_write, mut ws_read) = ws.split();

    // Asynchronous line-by-line reading of standard input
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    println!("> Enter to send, Ctrl-C to exit");
    print!("> ");
    std::io::stdout().flush()?;

    loop {
        tokio::select! {
            // Print the WebSocket message
            msg = ws_read.next() => match msg {
                Some(Ok(Message::Text(txt))) => {
                    println!("< {}", txt);
                    print!("> ");
                    std::io::stdout().flush()?;
                }
                Some(Ok(Message::Binary(bin))) => {
                    println!("< [binary {} bytes]", bin.len());
                    print!("> ");
                    std::io::stdout().flush()?;
                }
                Some(Ok(Message::Close(_))) => {
                    println!("[server closed connection]");
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => { return Err(e.into()); }
                None => break,
            },

            // Send the server from input message
            line = lines.next_line() => match line? {
                Some(text) => {
                    ws_write.send(Message::Text(text)).await?;
                }
                None => break,
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url() {
        let url = url_from_host("localhost", 1234);
        assert_eq!(url, "ws://localhost:1234/");
    }
}
