use super::*;

#[tokio::test]
async fn absolute_form_is_forwarded_as_origin_form_with_regenerated_host() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let deny_spoofed_host = AclRule {
        id: RuleId::new("deny-spoofed-host-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "host".to_owned(),
            value_contains: Some("attacker.invalid".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_spoofed_host], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/path?q=1 HTTP/1.1\r\nHost: attacker.invalid\r\nProxy-Authorization: Basic secret\r\nConnection: x-remove\r\nX-Remove: yes\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut body = [0_u8; 5];
    client.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&body, b"hello");
    drop(client);
    let upstream_request = observed_request.await.unwrap();
    origin_task.await.unwrap();
    assert!(upstream_request.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
    assert!(upstream_request.contains(&format!("host: {origin}\r\n")));
    assert!(
        !upstream_request
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    assert!(!upstream_request.to_ascii_lowercase().contains("x-remove:"));
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::HttpRequestObserved { .. }))
    );
    assert!(events.iter().any(|event| matches!(
        event.event,
        AuditEvent::HttpResponseObserved { status: 200, .. }
    )));
}

#[tokio::test]
async fn head_response_preserves_representation_content_length_without_a_body() {
    let (origin, origin_task) =
        spawn_fixed_origin(b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\nConnection: close\r\n\r\n")
            .await;
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "HEAD http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await)
        .unwrap()
        .to_ascii_lowercase();
    assert!(response_head.starts_with("http/1.1 200"));
    assert!(response_head.contains("content-length: 123\r\n"));
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert!(body.is_empty());

    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}

#[tokio::test]
async fn no_content_response_does_not_gain_a_content_length() {
    let (origin, origin_task) =
        spawn_fixed_origin(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await;
    let (services, _audit) = services(Vec::new(), local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await)
        .unwrap()
        .to_ascii_lowercase();
    assert!(response_head.starts_with("http/1.1 204"));
    assert!(!response_head.contains("content-length:"));
    let mut body = Vec::new();
    timeout(Duration::from_secs(1), client.read_to_end(&mut body))
        .await
        .unwrap()
        .unwrap();
    assert!(body.is_empty());

    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
}
