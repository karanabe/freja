//! Local HTTP contracts for the browser fixture and its bounded interpretation.
use serde_json::Value;
mod support;
use support::{TestServer, response_body};

async fn send(
    server: &TestServer,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> Vec<u8> {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: fixture.test\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(body);
    server.request(&request).await
}

#[tokio::test]
async fn browser_assets_are_local_and_json_contracts_remain_json() {
    let server = TestServer::spawn().await;
    for (path, mime) in [
        ("/lab", "text/html"),
        ("/lab/app.js", "text/javascript"),
        ("/lab/style.css", "text/css"),
    ] {
        let response = send(&server, "GET", path, b"", "text/plain").await;
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"));
        assert!(text.contains(mime));
        assert!(text.contains("cache-control: no-store"));
        assert!(text.contains("connect-src 'self'"));
        assert!(text.contains("form-action 'none'"));
    }
    for path in ["/", "/get?case=old", "/healthz"] {
        let response = send(&server, "GET", path, b"", "text/plain").await;
        let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
        assert!(json.get("lab").is_none());
        assert!(String::from_utf8_lossy(&response).contains("application/json"));
    }
}

#[tokio::test]
async fn get_and_post_preserve_encoding_and_interpret_empty_unicode_and_delimiters() {
    let server = TestServer::spawn().await;
    for (encoded, decoded) in [
        ("", ""),
        ("+", " "),
        ("hello", "hello"),
        ("%E6%97%A5%E6%9C%AC%E8%AA%9E+%26%3D%2B", "日本語 &=+"),
    ] {
        let data = format!("case=sample&message={encoded}");
        for method in ["GET", "POST"] {
            let path = if method == "GET" {
                format!("/lab/get?{data}")
            } else {
                "/lab/post".to_owned()
            };
            let body = if method == "POST" {
                data.as_bytes()
            } else {
                b""
            };
            let response = send(
                &server,
                method,
                &path,
                body,
                "application/x-www-form-urlencoded",
            )
            .await;
            assert!(response.starts_with(b"HTTP/1.1 200"));
            let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
            assert_eq!(json["http_version"], "HTTP/1.1");
            assert_eq!(json["received"]["method"], method);
            assert_eq!(json["received"]["uri"], path);
            assert_eq!(
                json["received"]["body"]["utf8"],
                std::str::from_utf8(body).unwrap()
            );
            assert_eq!(json["interpretation"]["message"], decoded);
            assert!(json["arrival"].as_str().unwrap().contains("unverified"));
        }
    }
}

#[tokio::test]
async fn malformed_edits_remain_received_bytes_without_invented_fields() {
    let server = TestServer::spawn().await;
    for (body, content_type, status) in [
        (
            "plain edited text",
            "application/x-www-form-urlencoded",
            400,
        ),
        (
            "case=x&message=%ZZ",
            "application/x-www-form-urlencoded",
            400,
        ),
        (
            "case=x&message=%FF",
            "application/x-www-form-urlencoded",
            400,
        ),
        ("case=x&case=y", "application/x-www-form-urlencoded", 400),
        (
            "case=x&message=one&extra=two",
            "application/x-www-form-urlencoded",
            400,
        ),
        ("case=x", "application/x-www-form-urlencoded", 400),
        ("case=&message=", "application/x-www-form-urlencoded", 400),
        ("case=x&message=yes", "text/plain", 415),
    ] {
        let response = send(&server, "POST", "/lab/post", body.as_bytes(), content_type).await;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")));
        let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
        assert_eq!(json["received"]["body"]["utf8"], body);
        assert_eq!(json["interpretation"]["kind"], "unavailable");
        assert!(json["interpretation"].get("message").is_none());
    }
    // A broken edit does not damage the next independently received request.
    let response = send(
        &server,
        "POST",
        "/lab/post",
        b"case=next&message=",
        "application/x-www-form-urlencoded",
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
}

#[tokio::test]
async fn field_input_and_total_output_limits_apply_without_browser_validation() {
    let server = TestServer::spawn().await;
    for (value, status) in [
        ("x".repeat(256), 200),
        ("x".repeat(257), 400),
        ("%E7%95%8C".repeat(85), 200),
        ("%E7%95%8C".repeat(86), 400),
    ] {
        let body = format!("case=limit&message={value}");
        let response = send(
            &server,
            "POST",
            "/lab/post",
            body.as_bytes(),
            "application/x-www-form-urlencoded",
        )
        .await;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")));
        assert!(response_body(&response).len() <= 64 * 1024);
    }
    for size in [2048, 2049] {
        let body = vec![b'x'; size];
        let response = send(
            &server,
            "POST",
            "/lab/post",
            &body,
            "application/x-www-form-urlencoded",
        )
        .await;
        let status = if size == 2048 { 400 } else { 413 };
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")));
        let query = format!("/lab/get?{}", "x".repeat(size));
        let response = send(&server, "GET", &query, b"", "text/plain").await;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {status}")));
    }
    let response = send(&server, "POST", "/lab/post", &vec![1; 2048], "text/plain").await;
    assert!(response_body(&response).len() <= 64 * 1024);
    let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
    assert_eq!(json["received"]["body"]["byte_length"], 2048);
}

#[tokio::test]
async fn bounded_headers_and_markup_are_data_not_html() {
    let server = TestServer::spawn().await;
    let body = "case=markup&message=%3Cscript%3Ealert%281%29%3C%2Fscript%3E%1B";
    let request = format!(
        "POST /lab/post HTTP/1.1\r\nHost: fixture.test\r\nX-Oversized: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        "x".repeat(1025),
        body.len()
    );
    let response = server.request(request.as_bytes()).await;
    let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
    assert_eq!(json["headers_omitted"], true);
    assert!(json["received"]["headers"].get("x-oversized").is_none());
    assert_eq!(
        json["interpretation"]["message"],
        "<script>alert(1)</script>\x1b"
    );
    assert!(String::from_utf8_lossy(&response).contains("application/json"));
    assert!(!response.contains(&0x1b));
}
