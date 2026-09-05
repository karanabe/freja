use std::net::SocketAddr;

use bytes::{Bytes, BytesMut};
use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{
    Direction, EvaluationTarget, HookMode, HttpRequestFacts, HttpResponseFacts, InspectionMode,
    Protocol, ReplayFacts, RequestedTargetFacts, ResolvedTargetFacts, SessionId, TransactionId,
};
use freja_policy::{
    PolicyFacts,
    hook::{
        HttpRequestHead, HttpResponseHead, HttpResponseSnapshot, RepeatFailureCategory,
        RepeatOutcome, RepeatRequest, RepeatResult, apply_head_mutation,
        normalize_replaced_body_headers,
    },
};
use http::{HeaderValue, Method, Request, Response, Version, header};
use http_body_util::BodyExt as _;
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::timeout,
};

use super::{
    CollectError, ProxyBody,
    body::{normalize_no_content_headers, response_has_no_content},
};
use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any, record_action},
    http::{
        body::{collect_bounded, full},
        headers,
        target::{ForwardScheme, ForwardTarget},
    },
    inspection::FlowInspector,
};

/// Sequential, tracked worker for bounded HTTP/1.1 repeat requests from the TUI.
///
/// Repeat requests never enter the interactive broker again. Every attempt
/// receives fresh correlation identifiers and re-runs current destination,
/// ACL, inspection, hook, TLS-authentication, and audit processing.
#[derive(Debug)]
pub struct HttpRepeatExecutor {
    receiver: mpsc::Receiver<RepeatRequest>,
    results: mpsc::Sender<RepeatResult>,
    services: DataPlaneServices,
    limits: ProxyLimits,
}

impl HttpRepeatExecutor {
    /// Creates a worker from independently bounded request and result channels.
    pub const fn new(
        receiver: mpsc::Receiver<RepeatRequest>,
        results: mpsc::Sender<RepeatResult>,
        services: DataPlaneServices,
        limits: ProxyLimits,
    ) -> Self {
        Self {
            receiver,
            results,
            services,
            limits,
        }
    }

    /// Runs until graceful shutdown. A disconnected TUI disables new work but
    /// does not terminate the process independently.
    ///
    /// # Errors
    ///
    /// Returns a data-plane error when critical audit publication fails.
    pub async fn run(mut self, mut shutdown: ShutdownSignal) -> Result<(), ProxyError> {
        loop {
            let command = tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                command = self.receiver.recv() => command,
            };
            let Some(command) = command else {
                shutdown.cancelled().await;
                return Ok(());
            };
            let result = self.execute(command, shutdown.clone()).await?;
            tokio::select! {
                () = shutdown.cancelled() => return Ok(()),
                sent = self.results.send(result) => {
                    if sent.is_err() {
                        shutdown.cancelled().await;
                        return Ok(());
                    }
                }
            }
        }
    }

    async fn execute(
        &self,
        command: RepeatRequest,
        mut shutdown: ShutdownSignal,
    ) -> Result<RepeatResult, ProxyError> {
        let session_id = SessionId::new();
        let transaction_id = TransactionId::new();
        let source_transaction_id = command.source.transaction_id;
        let context = audit_context(session_id, Some(transaction_id), &self.services);
        self.services.publish_flow_opened(
            session_id,
            command.source.source_ip.to_string(),
            command.request.uri.to_string(),
        );
        self.services
            .publish(AuditEnvelope {
                context,
                event: AuditEvent::HttpRepeatStarted {
                    source_session_id: command.source.session_id,
                    source_transaction_id,
                },
            })
            .await?;
        self.publish_request(session_id, transaction_id, &command)
            .await?;

        let outcome = match self
            .perform(&command, session_id, transaction_id, &mut shutdown)
            .await
        {
            Ok(response) => {
                self.publish_response(session_id, transaction_id, &response)
                    .await?;
                RepeatOutcome::Response(response)
            }
            Err(AttemptError::Category(category)) => RepeatOutcome::Failed(category),
            Err(AttemptError::Proxy(error)) => {
                if matches!(error, ProxyError::Audit(_)) {
                    return Err(error);
                }
                RepeatOutcome::Failed(failure_category(&error))
            }
        };
        let request_bytes = u64::try_from(command.request.body.bytes().len()).unwrap_or(u64::MAX);
        let response_bytes = match &outcome {
            RepeatOutcome::Response(response) => response.observed_body_bytes,
            RepeatOutcome::Failed(_) => 0,
        };
        let close_outcome = match &outcome {
            RepeatOutcome::Response(_) => "completed".to_owned(),
            RepeatOutcome::Failed(category) => failure_outcome(*category).to_owned(),
        };
        self.services
            .publish(AuditEnvelope {
                context: audit_context(session_id, Some(transaction_id), &self.services),
                event: AuditEvent::FlowClosed {
                    client_to_upstream_bytes: request_bytes,
                    upstream_to_client_bytes: response_bytes,
                    outcome: close_outcome,
                },
            })
            .await?;
        self.services
            .publish_flow_closed(session_id, request_bytes, response_bytes);
        Ok(RepeatResult {
            source_transaction_id,
            session_id,
            transaction_id,
            outcome,
        })
    }

    async fn publish_request(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        command: &RepeatRequest,
    ) -> Result<(), ProxyError> {
        self.services.publish_http_event(
            session_id,
            transaction_id,
            command.request.method.as_str().to_owned(),
            command.request.uri.to_string(),
            format!("{:?}", command.request.version),
            headers::presentation_headers(&command.request.headers),
        );
        self.services.publish_wire_capture_unavailable(
            session_id,
            transaction_id,
            Direction::HttpRequestBody,
            "repeat requests retain semantic snapshots, not ingress wire bytes".to_owned(),
        );
        self.services
            .publish(AuditEnvelope {
                context: audit_context(session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpRequestObserved {
                    method: command.request.method.as_str().to_owned(),
                    target: command.request.uri.to_string(),
                    headers: headers::audit_headers(&command.request.headers),
                },
            })
            .await
    }

    async fn publish_response(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        response: &HttpResponseSnapshot,
    ) -> Result<(), ProxyError> {
        self.services.publish_http_response_event(
            session_id,
            transaction_id,
            response.status.as_u16(),
            format!("{:?}", response.version),
            headers::presentation_headers(&response.headers),
        );
        self.services
            .publish(AuditEnvelope {
                context: audit_context(session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpResponseObserved {
                    status: response.status.as_u16(),
                    headers: headers::audit_headers(&response.headers),
                },
            })
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn perform(
        &self,
        command: &RepeatRequest,
        session_id: SessionId,
        transaction_id: TransactionId,
        shutdown: &mut ShutdownSignal,
    ) -> Result<HttpResponseSnapshot, AttemptError> {
        if command.request.version != Version::HTTP_11
            || command.request.method == Method::CONNECT
            || command.request.body.bytes().len() > self.limits.body_prefix_bytes
        {
            return Err(AttemptError::Category(
                RepeatFailureCategory::InvalidRequest,
            ));
        }
        headers::validate(&command.request.headers, self.limits.header_bytes)
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::InvalidRequest))?;
        let (target, scheme) = ForwardTarget::from_repeat(&command.request.uri)
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::InvalidRequest))?;
        if scheme == ForwardScheme::Https
            && self
                .services
                .tls_interceptor()
                .is_none_or(|interceptor| !interceptor.should_intercept(target.host()))
        {
            return Err(AttemptError::Category(RepeatFailureCategory::Tls));
        }
        let Some(origin_uri) = target.origin_uri().cloned() else {
            return Err(AttemptError::Category(
                RepeatFailureCategory::InvalidRequest,
            ));
        };
        let policy_path = origin_uri
            .path_and_query()
            .map_or("/", |value| value.as_str())
            .to_owned();
        let mut headers = command.request.headers.clone();
        headers::strip_hop_by_hop(&mut headers)
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::InvalidRequest))?;
        regenerate_host(&mut headers, target.authority())?;
        let requested = RequestedTargetFacts::new(
            command.source.source_ip,
            target.host().clone(),
            target.port(),
            Protocol::Http,
        );
        let addresses = authorize_and_resolve(
            &requested,
            &self.services,
            session_id,
            Some(transaction_id),
            self.limits.connect_timeout,
            shutdown,
        )
        .await
        .map_err(AttemptError::Proxy)?;
        self.evaluate_request_policy(
            &requested,
            &addresses,
            session_id,
            transaction_id,
            command.request.method.as_str(),
            &policy_path,
            &headers,
        )
        .await?;
        let (upstream, selected_address) =
            connect_any(&addresses, self.limits.connect_timeout, shutdown)
                .await
                .map_err(AttemptError::Proxy)?;

        self.apply_request_head_hooks(
            session_id,
            transaction_id,
            &command.request.method,
            &origin_uri,
            &mut headers,
        )
        .await?;
        regenerate_host(&mut headers, target.authority())?;
        let body = self
            .prepare_request_body(
                session_id,
                transaction_id,
                command.request.body.bytes().clone(),
                &mut headers,
                &ResolvedTargetFacts::new(requested.clone(), selected_address.ip()),
            )
            .await?;
        let mut request = Request::builder()
            .method(command.request.method.clone())
            .uri(origin_uri)
            .version(Version::HTTP_11)
            .body(full(body))
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::InvalidRequest))?;
        *request.headers_mut() = headers;

        match scheme {
            ForwardScheme::Http => {
                self.send_on(
                    upstream,
                    request,
                    session_id,
                    transaction_id,
                    &requested,
                    selected_address,
                    shutdown,
                )
                .await
            }
            ForwardScheme::Https => {
                let interceptor = self
                    .services
                    .tls_interceptor()
                    .ok_or(AttemptError::Category(RepeatFailureCategory::Tls))?;
                let tls = timeout(
                    self.limits.connect_timeout,
                    interceptor.connect_upstream(upstream, target.host(), Some(b"http/1.1")),
                )
                .await
                .map_err(|_| AttemptError::Category(RepeatFailureCategory::Tls))?
                .map_err(ProxyError::Tls)
                .map_err(AttemptError::Proxy)?;
                self.send_on(
                    tls,
                    request,
                    session_id,
                    transaction_id,
                    &requested,
                    selected_address,
                    shutdown,
                )
                .await
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_request_policy(
        &self,
        requested: &RequestedTargetFacts,
        addresses: &[SocketAddr],
        session_id: SessionId,
        transaction_id: TransactionId,
        method: &str,
        path: &str,
        request_headers: &http::HeaderMap,
    ) -> Result<(), AttemptError> {
        let snapshot = self.services.decision_snapshot();
        let policy_headers = headers::policy_headers(request_headers);
        let mut first_denial = None;
        for address in addresses {
            let facts = HttpRequestFacts::new(
                ResolvedTargetFacts::new(requested.clone(), address.ip()),
                method,
                path,
                policy_headers.clone(),
            );
            let context = audit_context(session_id, Some(transaction_id), &self.services);
            self.services
                .publish_replay_facts(context, ReplayFacts::HttpRequest(facts.clone()))
                .await
                .map_err(AttemptError::Proxy)?;
            let (decision, definition) = snapshot
                .policy()
                .evaluate_with_definition(PolicyFacts::HttpRequest(&facts));
            self.services
                .publish_decision(
                    context,
                    decision.clone(),
                    (definition, snapshot.enforcement()),
                    EvaluationTarget::Resolved(facts.target().clone()),
                )
                .await
                .map_err(AttemptError::Proxy)?;
            if !snapshot.permits(&decision) && first_denial.is_none() {
                first_denial = Some(decision);
            }
        }
        if let Some(decision) = first_denial {
            record_action(session_id, Some(transaction_id), &self.services, decision)
                .await
                .map_err(AttemptError::Proxy)?;
            return Err(AttemptError::Category(RepeatFailureCategory::PolicyDenied));
        }
        Ok(())
    }

    async fn apply_request_head_hooks(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        method: &Method,
        uri: &http::Uri,
        request_headers: &mut http::HeaderMap,
    ) -> Result<(), AttemptError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpRequestHead {
            method: method.clone(),
            uri: uri.clone(),
            headers: request_headers.clone(),
        };
        let result = self.services.hooks().request_head(&input).await;
        self.services
            .publish_hook_outcome(
                audit_context(session_id, Some(transaction_id), &self.services),
                "http-request-head",
                result.is_ok(),
            )
            .await
            .map_err(AttemptError::Proxy)?;
        let plan = result
            .map_err(ProxyError::Hook)
            .map_err(AttemptError::Proxy)?;
        apply_head_mutation(request_headers, &plan)
            .map_err(ProxyError::HookMutation)
            .map_err(AttemptError::Proxy)
    }

    async fn prepare_request_body(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        bytes: Bytes,
        request_headers: &mut http::HeaderMap,
        target: &ResolvedTargetFacts,
    ) -> Result<Bytes, AttemptError> {
        let mut inspection = FlowInspector::new(
            self.services.clone(),
            session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        )
        .with_target(target.clone());
        if !inspection
            .permits(Direction::HttpRequestBody, &bytes)
            .await
            .map_err(AttemptError::Proxy)?
        {
            return Err(AttemptError::Category(RepeatFailureCategory::Inspection));
        }
        let transformed = inspection
            .transform_http_body(
                Direction::HttpRequestBody,
                bytes,
                self.limits.body_prefix_bytes,
                true,
            )
            .await
            .map_err(AttemptError::Proxy)?;
        if transformed.replaced {
            normalize_replaced_body_headers(request_headers);
        }
        set_content_length(request_headers, transformed.bytes.len())?;
        Ok(transformed.bytes)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_on<Stream>(
        &self,
        upstream: Stream,
        request: Request<ProxyBody>,
        session_id: SessionId,
        transaction_id: TransactionId,
        requested: &RequestedTargetFacts,
        selected_address: SocketAddr,
        shutdown: &mut ShutdownSignal,
    ) -> Result<HttpResponseSnapshot, AttemptError>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let request_method = request.method().clone();
        let handshake = timeout(
            self.limits.connect_timeout,
            http1::handshake::<_, ProxyBody>(TokioIo::new(upstream)),
        )
        .await
        .map_err(|_| AttemptError::Category(RepeatFailureCategory::Upstream))?;
        let (mut sender, connection) = handshake
            .map_err(|source| ProxyError::UpstreamHttp {
                stage: "repeat handshake",
                source,
            })
            .map_err(AttemptError::Proxy)?;
        let connection_task = tokio::spawn(async move {
            connection.await.map_err(|source| ProxyError::UpstreamHttp {
                stage: "repeat connection",
                source,
            })
        });
        let response = tokio::select! {
            () = shutdown.cancelled() => Err(AttemptError::Category(RepeatFailureCategory::Shutdown)),
            result = timeout(self.limits.idle_timeout, sender.send_request(request)) => {
                result
                    .map_err(|_| AttemptError::Category(RepeatFailureCategory::Upstream))?
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "repeat request",
                        source,
                    })
                    .map_err(AttemptError::Proxy)
            }
        };
        let result = match response {
            Ok(response) => {
                self.process_response(
                    response,
                    session_id,
                    transaction_id,
                    requested,
                    selected_address,
                    &request_method,
                )
                .await
            }
            Err(error) => Err(error),
        };
        connection_task.abort();
        let _join_result = connection_task.await;
        result
    }

    async fn process_response(
        &self,
        mut response: Response<Incoming>,
        session_id: SessionId,
        transaction_id: TransactionId,
        requested: &RequestedTargetFacts,
        selected_address: SocketAddr,
        request_method: &Method,
    ) -> Result<HttpResponseSnapshot, AttemptError> {
        headers::validate(response.headers(), self.limits.header_bytes)
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::Upstream))?;
        self.evaluate_response_policy(
            session_id,
            transaction_id,
            requested,
            selected_address,
            &response,
        )
        .await?;
        self.apply_response_head_hooks(session_id, transaction_id, &mut response)
            .await?;
        headers::strip_hop_by_hop(response.headers_mut())
            .map_err(|_| AttemptError::Category(RepeatFailureCategory::Upstream))?;
        let (mut parts, body) = response.into_parts();
        if response_has_no_content(request_method, parts.status) {
            normalize_no_content_headers(request_method, parts.status, &mut parts.headers);
            return Ok(HttpResponseSnapshot {
                status: parts.status,
                version: parts.version,
                headers: parts.headers,
                body: Vec::new(),
                observed_body_bytes: 0,
                body_truncated: false,
            });
        }
        let inspection_target = ResolvedTargetFacts::new(requested.clone(), selected_address.ip());
        let (body, observed_body_bytes, body_truncated, replaced) = match self
            .services
            .inspection_mode()
        {
            InspectionMode::Preflight => {
                self.preflight_response_body(body, session_id, transaction_id, &inspection_target)
                    .await?
            }
            InspectionMode::Streaming => {
                self.streaming_response_body(
                    body,
                    session_id,
                    transaction_id,
                    &parts.headers,
                    &inspection_target,
                )
                .await?
            }
        };
        if replaced {
            normalize_replaced_body_headers(&mut parts.headers);
            set_content_length(
                &mut parts.headers,
                usize::try_from(observed_body_bytes).unwrap_or(usize::MAX),
            )?;
        }
        Ok(HttpResponseSnapshot {
            status: parts.status,
            version: parts.version,
            headers: parts.headers,
            body,
            observed_body_bytes,
            body_truncated,
        })
    }

    async fn evaluate_response_policy(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        requested: &RequestedTargetFacts,
        selected_address: SocketAddr,
        response: &Response<Incoming>,
    ) -> Result<(), AttemptError> {
        let snapshot = self.services.decision_snapshot();
        let facts = HttpResponseFacts::new(
            ResolvedTargetFacts::new(requested.clone(), selected_address.ip()),
            response.status().as_u16(),
            headers::policy_headers(response.headers()),
        );
        let context = audit_context(session_id, Some(transaction_id), &self.services);
        self.services
            .publish_replay_facts(context, ReplayFacts::HttpResponse(facts.clone()))
            .await
            .map_err(AttemptError::Proxy)?;
        let (decision, definition) = snapshot
            .policy()
            .evaluate_with_definition(PolicyFacts::HttpResponse(&facts));
        self.services
            .publish_decision(
                context,
                decision.clone(),
                (definition, snapshot.enforcement()),
                EvaluationTarget::Resolved(facts.target().clone()),
            )
            .await
            .map_err(AttemptError::Proxy)?;
        if snapshot.permits(&decision) {
            return Ok(());
        }
        record_action(session_id, Some(transaction_id), &self.services, decision)
            .await
            .map_err(AttemptError::Proxy)?;
        Err(AttemptError::Category(RepeatFailureCategory::PolicyDenied))
    }

    async fn apply_response_head_hooks(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        response: &mut Response<Incoming>,
    ) -> Result<(), AttemptError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpResponseHead {
            status: response.status(),
            headers: response.headers().clone(),
        };
        let result = self.services.hooks().response_head(&input).await;
        self.services
            .publish_hook_outcome(
                audit_context(session_id, Some(transaction_id), &self.services),
                "http-response-head",
                result.is_ok(),
            )
            .await
            .map_err(AttemptError::Proxy)?;
        let plan = result
            .map_err(ProxyError::Hook)
            .map_err(AttemptError::Proxy)?;
        apply_head_mutation(response.headers_mut(), &plan)
            .map_err(ProxyError::HookMutation)
            .map_err(AttemptError::Proxy)
    }

    async fn preflight_response_body(
        &self,
        body: Incoming,
        session_id: SessionId,
        transaction_id: TransactionId,
        target: &ResolvedTargetFacts,
    ) -> Result<(Vec<u8>, u64, bool, bool), AttemptError> {
        let bytes = collect_bounded(
            body,
            self.limits.body_prefix_bytes,
            self.limits.read_timeout,
        )
        .await
        .map_err(|error| match error {
            CollectError::Hyper(source) => AttemptError::Proxy(ProxyError::UpstreamHttp {
                stage: "repeat response body",
                source,
            }),
            CollectError::ReadTimedOut => AttemptError::Category(RepeatFailureCategory::Upstream),
            CollectError::LimitExceeded { .. } => {
                AttemptError::Category(RepeatFailureCategory::Inspection)
            }
        })?;
        let mut inspection = FlowInspector::new(
            self.services.clone(),
            session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        )
        .with_target(target.clone());
        if !inspection
            .permits(Direction::HttpResponseBody, &bytes)
            .await
            .map_err(AttemptError::Proxy)?
        {
            return Err(AttemptError::Category(RepeatFailureCategory::Inspection));
        }
        let transformed = inspection
            .transform_http_body(
                Direction::HttpResponseBody,
                bytes,
                self.limits.body_prefix_bytes,
                true,
            )
            .await
            .map_err(AttemptError::Proxy)?;
        let observed = u64::try_from(transformed.bytes.len()).unwrap_or(u64::MAX);
        let (body, truncated) =
            retain_prefix(&transformed.bytes, self.ui_content_bytes(), observed);
        Ok((body, observed, truncated, transformed.replaced))
    }

    async fn streaming_response_body(
        &self,
        mut body: Incoming,
        session_id: SessionId,
        transaction_id: TransactionId,
        response_headers: &http::HeaderMap,
        target: &ResolvedTargetFacts,
    ) -> Result<(Vec<u8>, u64, bool, bool), AttemptError> {
        let mut inspection = FlowInspector::new(
            self.services.clone(),
            session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        )
        .with_target(target.clone());
        let body_may_change = self.services.hooks().may_mutate_response_body();
        let decoded_replacement_allowed = !response_headers.contains_key(header::CONTENT_ENCODING);
        if body_may_change && !decoded_replacement_allowed {
            return Err(AttemptError::Category(RepeatFailureCategory::Inspection));
        }
        let maximum = self.ui_content_bytes();
        let mut retained = BytesMut::new();
        let mut observed = 0_u64;
        let mut replaced = false;
        loop {
            let frame = timeout(self.limits.read_timeout, body.frame())
                .await
                .map_err(|_| AttemptError::Category(RepeatFailureCategory::Upstream))?;
            let Some(frame) = frame else {
                break;
            };
            let frame = frame
                .map_err(|source| ProxyError::UpstreamHttp {
                    stage: "repeat response body",
                    source,
                })
                .map_err(AttemptError::Proxy)?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            if !inspection
                .permits(Direction::HttpResponseBody, &data)
                .await
                .map_err(AttemptError::Proxy)?
            {
                return Err(AttemptError::Category(RepeatFailureCategory::Inspection));
            }
            let transformed = inspection
                .transform_http_body(
                    Direction::HttpResponseBody,
                    data,
                    self.limits.body_prefix_bytes,
                    decoded_replacement_allowed,
                )
                .await
                .map_err(AttemptError::Proxy)?;
            replaced |= transformed.replaced;
            observed =
                observed.saturating_add(u64::try_from(transformed.bytes.len()).unwrap_or(u64::MAX));
            let remaining = maximum.saturating_sub(retained.len());
            retained
                .extend_from_slice(&transformed.bytes[..remaining.min(transformed.bytes.len())]);
        }
        let truncated = observed > u64::try_from(retained.len()).unwrap_or(u64::MAX);
        Ok((retained.to_vec(), observed, truncated, replaced))
    }

    fn ui_content_bytes(&self) -> usize {
        self.services.ui_capture_settings().map_or(
            self.limits.body_prefix_bytes,
            crate::UiCaptureSettings::content_bytes,
        )
    }
}

#[derive(Debug)]
enum AttemptError {
    Category(RepeatFailureCategory),
    Proxy(ProxyError),
}

fn regenerate_host(headers: &mut http::HeaderMap, authority: &str) -> Result<(), AttemptError> {
    let value = HeaderValue::from_str(authority)
        .map_err(|_| AttemptError::Category(RepeatFailureCategory::InvalidRequest))?;
    headers.insert(header::HOST, value);
    Ok(())
}

fn set_content_length(headers: &mut http::HeaderMap, length: usize) -> Result<(), AttemptError> {
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    let value = HeaderValue::from_str(&length.to_string())
        .map_err(|_| AttemptError::Category(RepeatFailureCategory::Internal))?;
    headers.insert(header::CONTENT_LENGTH, value);
    Ok(())
}

fn retain_prefix(bytes: &[u8], maximum: usize, observed: u64) -> (Vec<u8>, bool) {
    let retained = bytes[..maximum.min(bytes.len())].to_vec();
    let truncated = observed > u64::try_from(retained.len()).unwrap_or(u64::MAX);
    (retained, truncated)
}

const fn failure_category(error: &ProxyError) -> RepeatFailureCategory {
    match error {
        ProxyError::PolicyDenied { .. } | ProxyError::DetourLoop { .. } => {
            RepeatFailureCategory::PolicyDenied
        }
        ProxyError::Dns { .. }
        | ProxyError::DnsTimedOut { .. }
        | ProxyError::NoResolvedAddresses { .. } => RepeatFailureCategory::Dns,
        ProxyError::ConnectFailed { .. } | ProxyError::ConnectTimedOut { .. } => {
            RepeatFailureCategory::Connect
        }
        ProxyError::Tls(_) => RepeatFailureCategory::Tls,
        ProxyError::UpstreamHttp { .. } | ProxyError::UpstreamResponseTimedOut => {
            RepeatFailureCategory::Upstream
        }
        ProxyError::Hook(_) | ProxyError::HookMutation(_) => RepeatFailureCategory::Inspection,
        ProxyError::Audit(_) => RepeatFailureCategory::Audit,
        ProxyError::Shutdown => RepeatFailureCategory::Shutdown,
        ProxyError::Bind { .. }
        | ProxyError::LocalAddress(_)
        | ProxyError::Accept(_)
        | ProxyError::HttpConnection(_)
        | ProxyError::HttpUpgrade(_)
        | ProxyError::TunnelRegistration
        | ProxyError::InternalPolicy(_)
        | ProxyError::RelayRead { .. }
        | ProxyError::RelayWrite { .. }
        | ProxyError::Interactive(_)
        | ProxyError::InteractiveRejected
        | ProxyError::Socks(_)
        | ProxyError::ConcurrencyClosed
        | ProxyError::Join(_) => RepeatFailureCategory::Internal,
    }
}

const fn failure_outcome(category: RepeatFailureCategory) -> &'static str {
    match category {
        RepeatFailureCategory::InvalidRequest => "repeat-invalid-request",
        RepeatFailureCategory::PolicyDenied => "repeat-policy-denied",
        RepeatFailureCategory::Dns => "repeat-dns-failed",
        RepeatFailureCategory::Connect => "repeat-connect-failed",
        RepeatFailureCategory::Tls => "repeat-tls-failed",
        RepeatFailureCategory::Upstream => "repeat-upstream-failed",
        RepeatFailureCategory::Inspection => "repeat-inspection-failed",
        RepeatFailureCategory::Audit => "repeat-audit-failed",
        RepeatFailureCategory::Shutdown => "repeat-shutdown",
        RepeatFailureCategory::Internal => "repeat-internal-failure",
    }
}
