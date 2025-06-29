use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::{accept_async, tungstenite::Message};

use crate::error::Result;

pub async fn run(opts: super::WebsocketOpts) -> Result<()> {
    let bind_addr = format!("{}:{}", opts.url, opts.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    println!("WebSocket server listening on ws://{bind_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("new connection from {peer}");

        tokio::spawn(async move {
            match accept_async(stream).await {
                Ok(ws_stream) => {
                    let (mut w, mut r) = ws_stream.split();
                    while let Some(msg) = r.next().await {
                        match msg {
                            Ok(Message::Text(txt)) => {
                                println!("({peer}) {txt}");
                                if w.send(Message::Text(txt)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Message::Binary(bin)) => {
                                println!("({peer}) [binary {} bytes]", bin.len());
                                if w.send(Message::Binary(bin)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Message::Close(_)) | Err(_) => break,
                            _ => {}
                        }
                    }
                    println!("connection {peer} closed");
                }
                Err(e) => eprintln!("upgrade error from {peer}: {e}"),
            }
        });
    }
}
