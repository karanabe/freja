//! The actual standalone origin through Freja's existing HTTP/1.1/intercept
//! pipeline. Decisions are driven by a bounded test consumer, not a new UI API.
use std::{net::SocketAddr, time::Duration};

use axum::{
    http::{HeaderValue, Version},
    middleware,
};
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher};
use freja_domain::{
    EnforcementMode, HookMode, HttpForwardListener, InspectionMode, ListenEndpoint,
    PolicyGeneration,
};
use freja_policy::{
    AclPolicy, DestinationAccess, DestinationGuard, DestinationGuardSettings, InspectionProgram,
    RuleAction,
    hook::{
        BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookFailurePolicy,
        HookRegistry, HookRunner, HttpRequestMutationPlan, InteractiveBroker, InteractiveDecision,
        InterceptRequest, InterceptTimeoutPolicy, RepeatOutcome, RepeatRequest,
    },
};
use freja_proxy::{
    DataPlaneServices, HttpForwardServer, HttpRepeatExecutor, ProxyLimits, ShutdownSender,
    UiCaptureSettings, shutdown_channel,
};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

mod support;
use support::response_body;

struct Lab {
    origin: SocketAddr,
    proxy: SocketAddr,
    arrivals: mpsc::Receiver<()>,
    intercepts: mpsc::Receiver<InterceptRequest>,
    audit: mpsc::Receiver<AuditEnvelope>,
    services: DataPlaneServices,
    shutdown: ShutdownSender,
    proxy_task: JoinHandle<Result<(), freja_proxy::ProxyError>>,
    origin_task: JoinHandle<std::io::Result<()>>,
}

impl Lab {
    async fn start(decision_timeout: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = listener.local_addr().unwrap();
        let (arrival_sender, arrivals) = mpsc::channel(16);
        let app = freja_http_test_server::app().layer(middleware::from_fn(
            move |request, next: middleware::Next| {
                let sender = arrival_sender.clone();
                async move {
                    sender.try_send(()).unwrap();
                    next.run(request).await
                }
            },
        ));
        let origin_task = tokio::spawn(axum::serve(listener, app).into_future());
        let generation = PolicyGeneration::default();
        let (publisher, audit) =
            AuditPublisher::channel(256, AuditFailurePolicy::FailClosed).unwrap();
        let (broker, intercepts) =
            InteractiveBroker::channel(4, 2, decision_timeout, InterceptTimeoutPolicy::FailClosed)
                .unwrap();
        let services = DataPlaneServices::new(
            AclPolicy::new(generation, Vec::new(), RuleAction::Allow).unwrap(),
            DestinationGuard::new(DestinationGuardSettings {
                loopback: DestinationAccess::Allow,
                ..DestinationGuardSettings::default()
            })
            .unwrap(),
            EnforcementMode::Enforce,
            publisher,
        )
        .with_inspection(
            InspectionProgram::empty(generation),
            InspectionMode::Preflight,
        )
        .with_hooks(HookRunner::new(
            HookMode::Interactive,
            HookRegistry::default(),
            Duration::from_secs(1),
            HookFailurePolicy::FailClosed,
        ))
        .with_interactive_broker(broker)
        .with_ui_capture(UiCaptureSettings::new(16 * 1024, 4).unwrap());
        let server = HttpForwardServer::bind(
            HttpForwardListener::new(ListenEndpoint::new("127.0.0.1:0".parse().unwrap())),
            services.clone(),
            limits(),
        )
        .await
        .unwrap();
        let proxy = server.local_address();
        let (shutdown, signal) = shutdown_channel();
        let proxy_task = tokio::spawn(server.run(signal));
        Self {
            origin,
            proxy,
            arrivals,
            intercepts,
            audit,
            services,
            shutdown,
            proxy_task,
            origin_task,
        }
    }

    fn send(&self, method: &str, path: &str, body: &str) -> JoinHandle<Vec<u8>> {
        let proxy = self.proxy;
        let request = format!(
            "{method} http://{}{path} HTTP/1.1\r\nHost: ignored.invalid\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.origin,
            body.len()
        );
        tokio::spawn(async move {
            let mut stream = TcpStream::connect(proxy).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            timeout(
                Duration::from_secs(5),
                stream.take(128 * 1024).read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            response
        })
    }

    async fn paused(&mut self) -> InterceptRequest {
        timeout(Duration::from_secs(2), self.intercepts.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn assert_no_arrival(&mut self) {
        assert!(
            timeout(Duration::from_millis(60), self.arrivals.recv())
                .await
                .is_err()
        );
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        self.proxy_task.abort();
        self.origin_task.abort();
    }
}

fn limits() -> ProxyLimits {
    ProxyLimits::new(
        8,
        16 * 1024,
        16 * 1024,
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )
    .unwrap()
}

#[tokio::test]
async fn continue_and_post_edit_reach_origin_with_actual_http11_bytes() {
    let mut lab = Lab::start(Duration::from_secs(2)).await;
    // Entry GET can pause before a user even sees the form.
    let entry = lab.send("GET", "/lab", "");
    let pause = lab.paused().await;
    assert_eq!(pause.request.version, Version::HTTP_11);
    lab.assert_no_arrival().await;
    pause.response.send(InteractiveDecision::Continue).unwrap();
    assert!(
        String::from_utf8(entry.await.unwrap())
            .unwrap()
            .contains("One request. Follow it through.")
    );
    lab.arrivals.recv().await.unwrap();

    let body = "case=post-original&message=%E6%97%A5%E6%9C%AC%E8%AA%9E+%26%3D";
    let query = format!("/lab/get?{body}");
    for (method, path, input, edit) in [
        ("GET", query.as_str(), "", false),
        ("POST", "/lab/post", body, false),
        ("POST", "/lab/post", body, true),
    ] {
        let pending = lab.send(method, path, input);
        let pause = lab.paused().await;
        assert_eq!(pause.request.version, Version::HTTP_11);
        assert_eq!(pause.request.body.bytes().as_ref(), input.as_bytes());
        lab.assert_no_arrival().await;
        let action = if edit {
            InteractiveDecision::ModifyRequest(HttpRequestMutationPlan {
                head: HeadMutationPlan {
                    headers: vec![HeaderMutation::Set {
                        name: "x-lab-edit".parse().unwrap(),
                        value: HeaderValue::from_static("yes"),
                    }],
                },
                body: BodyMutationPlan::Replace(DecodedBody::new(
                    "case=post-edited&message=changed",
                )),
            })
        } else {
            InteractiveDecision::Continue
        };
        pause.response.send(action).unwrap();
        let response = pending.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
        assert_eq!(json["http_version"], "HTTP/1.1");
        assert_eq!(json["received"]["uri"], path);
        if edit {
            assert_eq!(json["interpretation"]["case"], "post-edited");
            assert_eq!(json["received"]["headers"]["x-lab-edit"][0], "yes");
            assert_eq!(
                json["received"]["body"]["utf8"],
                "case=post-edited&message=changed"
            );
        } else {
            assert_eq!(json["interpretation"]["message"], "日本語 &=");
            assert_eq!(json["received"]["body"]["utf8"], input);
        }
        lab.arrivals.recv().await.unwrap();
    }
}

#[tokio::test]
async fn reject_and_timeout_have_no_origin_request_and_distinct_audit_evidence() {
    for reject in [true, false] {
        let mut lab = Lab::start(Duration::from_millis(120)).await;
        let pending = lab.send("POST", "/lab/post", "case=not-arrived&message=no");
        let pause = lab.paused().await;
        let transaction = pause.context.transaction_id;
        if reject {
            pause.response.send(InteractiveDecision::Reject).unwrap();
        } else {
            // Keep the responder alive until the broker times out.
            timeout(Duration::from_secs(2), async {
                while !pause.response.is_closed() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        let response = pending.await.unwrap();
        assert!(response.starts_with(if reject {
            b"HTTP/1.1 403"
        } else {
            b"HTTP/1.1 504"
        }));
        assert!(!String::from_utf8_lossy(&response).contains("http11-browser-form"));
        lab.assert_no_arrival().await;
        let mut matched = false;
        while let Ok(event) = lab.audit.try_recv() {
            if event.context.transaction_id == Some(transaction) {
                matched |= if reject {
                    matches!(event.event, AuditEvent::ManualModification { ref action } if action == "reject")
                } else {
                    matches!(event.event, AuditEvent::ManualModification { ref action } if action == "failed")
                };
            }
        }
        assert!(
            matched,
            "missing distinct audit evidence for reject={reject}"
        );
    }
}

#[tokio::test]
async fn repeat_sends_an_additional_request_with_fresh_transaction_without_repausing() {
    let mut lab = Lab::start(Duration::from_secs(2)).await;
    let pending = lab.send("POST", "/lab/post", "case=repeat-01&message=one");
    let pause = lab.paused().await;
    let original_id = pause.context.transaction_id;
    let draft = RepeatRequest {
        source: pause.context,
        request: pause.request.clone(),
    };
    pause.response.send(InteractiveDecision::Continue).unwrap();
    assert!(pending.await.unwrap().starts_with(b"HTTP/1.1 200"));
    lab.arrivals.recv().await.unwrap();
    let (commands, receiver) = mpsc::channel(1);
    let (sender, mut results) = mpsc::channel(1);
    let (shutdown, signal) = shutdown_channel();
    let task = tokio::spawn(
        HttpRepeatExecutor::new(receiver, sender, lab.services.clone(), limits()).run(signal),
    );
    commands.send(draft).await.unwrap();
    let result = timeout(Duration::from_secs(2), results.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.source_transaction_id, original_id);
    assert_ne!(result.transaction_id, original_id);
    let RepeatOutcome::Response(response) = result.outcome else {
        panic!("expected origin response")
    };
    assert!(!response.body_truncated);
    let json: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(json["interpretation"]["case"], "repeat-01");
    lab.arrivals.recv().await.unwrap();
    assert!(
        timeout(Duration::from_millis(60), lab.intercepts.recv())
            .await
            .is_err()
    );
    shutdown.shutdown();
    timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn direct_echo_leaves_proxy_path_unverified_and_stopped_origin_does_not_echo() {
    let direct = support::TestServer::spawn().await;
    let response = direct.request(b"GET /lab/get?case=direct&message=control HTTP/1.1\r\nHost: fixture.test\r\nConnection: close\r\n\r\n").await;
    let json: Value = serde_json::from_slice(response_body(&response)).unwrap();
    assert!(json["arrival"].as_str().unwrap().contains("unverified"));
    let mut lab = Lab::start(Duration::from_secs(1)).await;
    lab.origin_task.abort();
    assert!((&mut lab.origin_task).await.is_err());
    let pending = lab.send("POST", "/lab/post", "case=stopped&message=no-echo");
    let response = pending.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 502"));
    assert!(!String::from_utf8_lossy(&response).contains("http11-browser-form"));
}
