use super::*;

#[tokio::test]
async fn denied_http_destination_returns_synthetic_forbidden() {
    let deny_host = AclRule {
        id: RuleId::new("deny-blocked-host").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("blocked.test").unwrap(),
        )),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_host], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://blocked.test/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-blocked-host")
    )));
}

#[tokio::test]
async fn request_header_policy_denial_happens_before_upstream_connect() {
    let deny_header = AclRule {
        id: RuleId::new("deny-request-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "x-freja-block".to_owned(),
            value_contains: Some("yes".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_header], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            b"GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: ignored.invalid\r\nX-Freja-Block: yes\r\n\r\n",
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-request-header")
    )));
}

#[tokio::test]
async fn response_header_policy_denial_replaces_the_upstream_response() {
    let (origin, observed_request, origin_task) = spawn_origin().await;
    let deny_header = AclRule {
        id: RuleId::new("deny-response-header").unwrap(),
        matcher: MatchExpression::HttpHeader(HttpHeaderMatcher {
            name: "x-upstream".to_owned(),
            value_contains: Some("yes".to_owned()),
        }),
        action: RuleAction::Deny,
    };
    let (services, mut audit) = services(vec![deny_header], local_access());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    observed_request.await.unwrap();
    origin_task.await.unwrap();
    stop_proxy(shutdown, proxy_task).await;
    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("deny-response-header")
                && decision.trace.evaluated_stage == freja_domain::PolicyStage::HttpResponse
    )));
}

#[tokio::test]
async fn hostname_allowed_by_acl_is_forbidden_after_loopback_resolution() {
    let allow_hostname = AclRule {
        id: RuleId::new("allow-localhost").unwrap(),
        matcher: MatchExpression::DestinationHost(HostPattern::Exact(
            HostName::new("localhost").unwrap(),
        )),
        action: RuleAction::Allow,
    };
    let (services, mut audit) = services(vec![allow_hostname], DestinationGuardSettings::default());
    let (proxy, shutdown, proxy_task) = bind_proxy(vec![Port::HTTPS], services).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    client
        .write_all(b"GET http://localhost:9/ HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n")
        .await
        .unwrap();

    let response_head = String::from_utf8(read_head(&mut client).await).unwrap();
    assert!(response_head.starts_with("HTTP/1.1 403"));
    drop(client);
    stop_proxy(shutdown, proxy_task).await;

    let events = collect_events(&mut audit);
    assert!(events.iter().any(|event| matches!(
        &event.event,
        AuditEvent::ActionExecuted { decision }
            if decision.trace.matched_rule.as_ref().map(RuleId::as_str)
                == Some("protect-loopback-destination")
    )));
}
