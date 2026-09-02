//! End-to-end HTTP checks for the Axum test origin.

use std::{net::SocketAddr, str};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct TestServer {
    address: SocketAddr,
    task: JoinHandle<std::io::Result<()>>,
}

impl TestServer {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(axum::serve(listener, freja_http_test_server::app()).into_future());
        Self { address, task }
    }

    async fn request(&self, request: &[u8]) -> Vec<u8> {
        let mut stream = TcpStream::connect(self.address).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn response_body(response: &[u8]) -> &[u8] {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    &response[separator + 4..]
}

#[tokio::test]
async fn get_echoes_request_target_and_headers() {
    let server = TestServer::spawn().await;
    let response = server
        .request(
            b"GET /get?name=freja HTTP/1.1\r\nHost: origin.test\r\nX-Trace: visible\r\nConnection: close\r\n\r\n",
        )
        .await;

    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body: Value = serde_json::from_slice(response_body(&response)).unwrap();
    assert_eq!(body["method"], "GET");
    assert_eq!(body["uri"], "/get?name=freja");
    assert_eq!(body["headers"]["x-trace"][0], "visible");
    assert_eq!(body["body"]["byte_length"], 0);
}

#[tokio::test]
async fn post_echoes_text_and_binary_safe_body_forms() {
    let server = TestServer::spawn().await;
    let response = server
        .request(
            b"POST /post HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello freja",
        )
        .await;

    let body: Value = serde_json::from_slice(response_body(&response)).unwrap();
    assert_eq!(body["method"], "POST");
    assert_eq!(body["body"]["byte_length"], 11);
    assert_eq!(body["body"]["utf8"], "hello freja");
    assert_eq!(body["body"]["base64"], "aGVsbG8gZnJlamE=");
}

#[tokio::test]
async fn health_head_any_method_and_delay_routes_are_observable() {
    let server = TestServer::spawn().await;

    let health = server
        .request(b"GET /healthz HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await;
    let health_body: Value = serde_json::from_slice(response_body(&health)).unwrap();
    assert_eq!(health_body["status"], "ok");

    let head = server
        .request(b"HEAD /head HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await;
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response_body(&head).is_empty());

    let anything = server
        .request(
            b"PROPFIND /anything/nested/path HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
    let anything_body: Value = serde_json::from_slice(response_body(&anything)).unwrap();
    assert_eq!(anything_body["method"], "PROPFIND");
    assert_eq!(anything_body["uri"], "/anything/nested/path");

    let delayed = server
        .request(
            b"POST /delay/0 HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
    let delayed_body: Value = serde_json::from_slice(response_body(&delayed)).unwrap();
    assert_eq!(delayed_body["method"], "POST");
    assert_eq!(delayed_body["uri"], "/delay/0");
}

#[tokio::test]
async fn method_status_and_redirect_routes_are_observable() {
    let server = TestServer::spawn().await;

    for (method, path) in [
        ("PUT", "/put"),
        ("PATCH", "/patch"),
        ("DELETE", "/delete"),
        ("OPTIONS", "/options"),
    ] {
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let response = server.request(request.as_bytes()).await;
        let body: Value = serde_json::from_slice(response_body(&response)).unwrap();
        assert_eq!(body["method"], method);
    }

    let status = server
        .request(b"GET /status/418 HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await;
    assert!(status.starts_with(b"HTTP/1.1 418 I'm a teapot\r\n"));

    let redirect = server
        .request(b"GET /redirect/2 HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await;
    let redirect_text = str::from_utf8(&redirect).unwrap().to_ascii_lowercase();
    assert!(redirect_text.starts_with("http/1.1 307 temporary redirect\r\n"));
    assert!(redirect_text.contains("location: /redirect/1\r\n"));
}

#[tokio::test]
async fn stream_and_sized_response_endpoints_return_requested_content() {
    let server = TestServer::spawn().await;
    let stream = server
        .request(
            b"GET /stream/3?interval_ms=0 HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n",
        )
        .await;
    let stream_text = str::from_utf8(response_body(&stream)).unwrap();
    assert!(stream_text.contains("chunk-0000"));
    assert!(stream_text.contains("chunk-0001"));
    assert!(stream_text.contains("chunk-0002"));

    let bytes = server
        .request(b"GET /bytes/32 HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n")
        .await;
    assert_eq!(response_body(&bytes), &[b'x'; 32]);
}

#[tokio::test]
async fn route_resource_limits_return_bad_request() {
    let server = TestServer::spawn().await;

    for path in [
        "/status/199",
        "/redirect/11",
        "/delay/30001",
        "/stream/0",
        "/stream/1000?interval_ms=1000",
        "/bytes/8388609",
    ] {
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: origin.test\r\nConnection: close\r\n\r\n");
        let response = server.request(request.as_bytes()).await;
        assert!(
            response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "unexpected response for {path}: {}",
            String::from_utf8_lossy(&response)
        );
    }
}

#[tokio::test]
async fn request_body_limit_is_applied_before_routing() {
    let server = TestServer::spawn().await;
    let body = vec![b'x'; freja_http_test_server::MAX_REQUEST_BODY_BYTES + 1];
    let mut request = format!(
        "POST /anything HTTP/1.1\r\nHost: origin.test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend(body);

    let response = server.request(&request).await;

    assert!(response.starts_with(b"HTTP/1.1 413 Payload Too Large\r\n"));
}
