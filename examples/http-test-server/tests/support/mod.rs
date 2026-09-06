use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

pub struct TestServer {
    pub address: SocketAddr,
    task: JoinHandle<std::io::Result<()>>,
}

impl TestServer {
    pub async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(axum::serve(listener, freja_http_test_server::app()).into_future());
        Self { address, task }
    }

    pub async fn request(&self, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.take(16 * 1024 * 1024).read_to_end(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        response
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn response_body(response: &[u8]) -> &[u8] {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    &response[separator + 4..]
}
