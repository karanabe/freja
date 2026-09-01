use super::*;

#[tokio::test]
async fn tui_capture_preserves_exact_http1_request_and_response_bytes() {
    let response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nX-Raw: yes\r\n\r\nok";
    let (origin, origin_task) = spawn_fixed_origin(response).await;
    let (services, _audit) = services(Vec::new(), local_access());
    let sink = RecordingEventSink::default();
    let services = services
        .with_ui_capture(UiCaptureSettings::new(64 * 1_024, 16).unwrap())
        .with_event_sink(sink.clone());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let request = format!(
        "POST http://{origin}/raw HTTP/1.1\r\nHost: deliberately-wrong.invalid\r\nX-Original: yes\r\nContent-Length: 3\r\n\r\nraw"
    );
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(request.as_bytes()).await.unwrap();

    let head = read_head(&mut client).await;
    let mut body = [0_u8; 2];
    client.read_exact(&mut body).await.unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    assert_eq!(&body, b"ok");
    drop(client);
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;

    let events = sink.events();
    let raw_request = events.iter().find_map(|event| match event {
        DataPlaneEvent::WireCaptured {
            direction: Direction::HttpRequestBody,
            bytes,
            truncated,
            ..
        } => Some((bytes.clone(), *truncated)),
        _ => None,
    });
    let raw_response = events.iter().find_map(|event| match event {
        DataPlaneEvent::WireCaptured {
            direction: Direction::HttpResponseBody,
            bytes,
            truncated,
            ..
        } => Some((bytes.clone(), *truncated)),
        _ => None,
    });
    assert_eq!(raw_request, Some((request.into_bytes(), false)));
    assert_eq!(raw_response, Some((response.to_vec(), false)));
}
