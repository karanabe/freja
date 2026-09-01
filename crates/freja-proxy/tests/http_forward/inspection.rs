use super::*;

#[tokio::test]
async fn preflight_request_body_detection_returns_block_page_before_forwarding() {
    let (origin, origin_task) = spawn_body_origin(b"ok").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpRequestBody, EnforcementMode::Enforce);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://{origin}/upload HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Length: 7\r\n\r\nMALWARE"
            )
            .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    let upstream_bytes = origin_task.await.unwrap();
    assert!(upstream_bytes.is_empty());
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FindingDetected { finding }
            if finding.direction == Direction::HttpRequestBody
    )));
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::HttpResponseObserved { status: 403, .. }
    )));
}

#[tokio::test]
async fn preflight_response_body_detection_replaces_upstream_response() {
    let (origin, origin_task) = spawn_body_origin(b"MALWARE").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpResponseBody, EnforcementMode::Enforce);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/download HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    assert!(!origin_task.await.unwrap().is_empty());
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::FindingDetected { finding }
            if finding.direction == Direction::HttpResponseBody
    )));
}

#[tokio::test]
async fn observe_mode_records_response_body_finding_without_replacement() {
    let (origin, origin_task) = spawn_body_origin(b"MALWARE").await;
    let (services, mut audit) =
        inspected_services(Direction::HttpResponseBody, EnforcementMode::Observe);
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/download HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    let mut body = [0_u8; 7];
    client.read_exact(&mut body).await.unwrap();
    assert!(response_head.starts_with("HTTP/1.1 200"));
    assert_eq!(&body, b"MALWARE");
    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::InspectionEvaluated { .. }))
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, AuditEvent::ActionExecuted { .. }))
    );
}
