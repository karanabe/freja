use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::{
    Decision, DecisionTrace, Direction, EnforcementAction, HookMode, HttpReject, HttpRequestFacts,
    HttpResponseFacts, InspectionMode, MatchReason, PolicyStage, Protocol, ProxyAuthentication,
    ReplayFacts, RequestedTargetFacts, ResolvedTargetFacts, RuleId, SessionId, TransactionId,
};
use freja_policy::{
    PolicyFacts,
    hook::{
        HttpRequestHead, HttpResponseHead, InteractiveDecision, InterceptStage,
        apply_head_mutation, normalize_replaced_body_headers,
    },
};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use http_body_util::BodyExt;
use hyper::{
    body::Incoming,
    client::conn::{http1, http2},
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use super::{
    body::{BodyError, BodyFrame, CollectError, ProxyBody, channel, collect_bounded, full},
    headers,
    target::ForwardTarget,
};
use crate::{
    DataPlaneServices, ProxyError, ProxyLimits, ShutdownSignal,
    destination::{audit_context, authorize_and_resolve, connect_any, record_action},
    inspection::{BodyTransform, FlowInspector},
    tcp::relay::{RelayLimits, RelayStats, RelayTermination, relay},
};

pub(super) type ConnectionTaskHandle = JoinHandle<Result<(), ProxyError>>;

#[derive(Clone)]
pub(super) struct HttpService {
    peer: SocketAddr,
    session_id: SessionId,
    connect_port_rule: RuleId,
    connect_ports: freja_domain::HttpForwardListener,
    services: DataPlaneServices,
    limits: ProxyLimits,
    shutdown: ShutdownSignal,
    task_sender: mpsc::Sender<ConnectionTaskHandle>,
}

impl HttpService {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        peer: SocketAddr,
        session_id: SessionId,
        connect_port_rule: RuleId,
        connect_ports: freja_domain::HttpForwardListener,
        services: DataPlaneServices,
        limits: ProxyLimits,
        shutdown: ShutdownSignal,
        task_sender: mpsc::Sender<ConnectionTaskHandle>,
    ) -> Self {
        Self {
            peer,
            session_id,
            connect_port_rule,
            connect_ports,
            services,
            limits,
            shutdown,
            task_sender,
        }
    }

    pub(super) async fn handle(
        &self,
        request: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let transaction_id = TransactionId::new();
        self.audit_request(transaction_id, &request).await?;
        if let Some(authentication) = self.connect_ports.authentication() {
            let authenticated = authenticate_proxy_request(request.headers(), authentication);
            self.services
                .publish(AuditEnvelope {
                    context: audit_context(self.session_id, Some(transaction_id), &self.services),
                    event: AuditEvent::ProxyAuthentication {
                        outcome: if authenticated {
                            "accepted"
                        } else {
                            "rejected"
                        }
                        .to_owned(),
                    },
                })
                .await?;
            if !authenticated {
                let response = proxy_authentication_required(authentication);
                let status = response.status().as_u16();
                let response_headers = headers::audit_headers(response.headers());
                self.audit_response(transaction_id, status, response_headers)
                    .await?;
                return Ok(response);
            }
        }
        let response = if request.method() == Method::CONNECT {
            self.connect(request, transaction_id).await
        } else {
            self.forward(request, transaction_id).await
        };
        let response = match response {
            Ok(response) => response,
            Err(error) => response_for_error(error)?,
        };
        let status = response.status().as_u16();
        let response_headers = headers::audit_headers(response.headers());
        self.audit_response(transaction_id, status, response_headers)
            .await?;
        Ok(response)
    }

    async fn handle_intercepted(
        &self,
        request: Request<Incoming>,
        target: &ForwardTarget,
        selected_address: SocketAddr,
        protocol: InterceptedProtocol,
        upstream: &Arc<Mutex<InterceptedUpstreamSender>>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        let transaction_id = TransactionId::new();
        self.audit_request(transaction_id, &request).await?;
        let response = self
            .forward_intercepted(
                request,
                target,
                selected_address,
                transaction_id,
                protocol,
                upstream,
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(error) => response_for_error(error)?,
        };
        self.audit_response(
            transaction_id,
            response.status().as_u16(),
            headers::audit_headers(response.headers()),
        )
        .await?;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_intercepted(
        &self,
        mut request: Request<Incoming>,
        target: &ForwardTarget,
        selected_address: SocketAddr,
        transaction_id: TransactionId,
        protocol: InterceptedProtocol,
        upstream: &Arc<Mutex<InterceptedUpstreamSender>>,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if request.method() == Method::CONNECT {
            return Ok(text_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "nested CONNECT is not supported\n",
            ));
        }
        if let Err(error) = headers::validate(request.headers(), self.limits.header_bytes) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or("/", |value| value.as_str())
            .to_owned();
        if let Err(error) = headers::strip_hop_by_hop(request.headers_mut()) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        if !regenerate_host(request.headers_mut(), target.authority()) {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT authority",
            ));
        }
        let Some(uri) = intercepted_upstream_uri(protocol, target.authority(), &path_and_query)
        else {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid intercepted request target",
            ));
        };
        *request.uri_mut() = uri;
        *request.version_mut() = protocol.http_version();

        let requested = RequestedTargetFacts::new(
            self.peer.ip(),
            target.host().clone(),
            target.port(),
            Protocol::Http,
        );
        if let Some(response) = self
            .evaluate_http_policy(
                &requested,
                &[selected_address],
                transaction_id,
                request.method().as_str(),
                &path_and_query,
                request.headers(),
            )
            .await?
        {
            return Ok(response);
        }
        self.apply_request_head_hooks(transaction_id, &mut request)
            .await?;
        if !regenerate_host(request.headers_mut(), target.authority()) {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid CONNECT authority",
            ));
        }
        let request_method = request.method().clone();
        let request = match self.prepare_request_body(request, transaction_id).await? {
            Ok(request) => request,
            Err(response) => return Ok(response),
        };
        let response = {
            let mut sender = upstream.lock().await;
            match timeout(self.limits.idle_timeout, sender.send_request(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(ProxyError::UpstreamResponseTimedOut),
            }
        };
        self.finish_response(
            transaction_id,
            response,
            &requested,
            selected_address,
            &request_method,
        )
        .await
    }

    async fn forward(
        &self,
        mut request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if let Err(error) = headers::validate(request.headers(), self.limits.header_bytes) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        let target = match ForwardTarget::from_absolute(request.uri()) {
            Ok(target) => target,
            Err(error) => return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
        };
        let policy_path = target.origin_uri().map_or_else(
            || "/".to_owned(),
            |uri| {
                uri.path_and_query()
                    .map_or("/", |value| value.as_str())
                    .to_owned()
            },
        );
        if let Err(error) = headers::strip_hop_by_hop(request.headers_mut()) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        if !regenerate_host(request.headers_mut(), target.authority()) {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid target authority",
            ));
        }
        if let Some(origin_uri) = target.origin_uri() {
            *request.uri_mut() = origin_uri.clone();
        }
        *request.version_mut() = Version::HTTP_11;
        let requested = RequestedTargetFacts::new(
            self.peer.ip(),
            target.host().clone(),
            target.port(),
            Protocol::Http,
        );
        let mut shutdown = self.shutdown.clone();
        let addresses = match authorize_and_resolve(
            &requested,
            &self.services,
            self.session_id,
            Some(transaction_id),
            self.limits.connect_timeout,
            &mut shutdown,
        )
        .await
        {
            Ok(addresses) => addresses,
            Err(error) => return response_for_error(error),
        };
        if let Some(response) = self
            .evaluate_http_policy(
                &requested,
                &addresses,
                transaction_id,
                request.method().as_str(),
                &policy_path,
                request.headers(),
            )
            .await?
        {
            return Ok(response);
        }
        let (upstream, selected_address) =
            match connect_any(&addresses, self.limits.connect_timeout, &mut shutdown).await {
                Ok(connected) => connected,
                Err(error) => return response_for_error(error),
            };

        self.apply_request_head_hooks(transaction_id, &mut request)
            .await?;
        if !regenerate_host(request.headers_mut(), target.authority()) {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "invalid target authority",
            ));
        }

        let request_method = request.method().clone();
        let request = match self.prepare_request_body(request, transaction_id).await? {
            Ok(request) => request,
            Err(response) => return Ok(response),
        };
        let response = match self.send_upstream_request(upstream, request).await {
            Ok(response) => response,
            Err(error) => return response_for_error(error),
        };
        self.finish_response(
            transaction_id,
            response,
            &requested,
            selected_address,
            &request_method,
        )
        .await
    }

    async fn connect(
        &self,
        mut request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if let Err(error) = headers::validate(request.headers(), self.limits.header_bytes) {
            return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string()));
        }
        let target = match ForwardTarget::from_connect(request.uri()) {
            Ok(target) => target,
            Err(error) => return Ok(text_response(StatusCode::BAD_REQUEST, &error.to_string())),
        };
        if !self.connect_ports.allows_connect_port(target.port()) {
            let snapshot = self.services.decision_snapshot();
            let decision = self.connect_port_denial(target.port(), &snapshot);
            self.services
                .publish_decision(
                    audit_context(self.session_id, Some(transaction_id), &self.services),
                    decision.clone(),
                )
                .await?;
            if !snapshot.permits(&decision) {
                record_action(
                    self.session_id,
                    Some(transaction_id),
                    &self.services,
                    decision.clone(),
                )
                .await?;
                return response_for_error(ProxyError::PolicyDenied { decision });
            }
        }

        let requested = RequestedTargetFacts::new(
            self.peer.ip(),
            target.host().clone(),
            target.port(),
            Protocol::Http,
        );
        let mut shutdown = self.shutdown.clone();
        let addresses = match authorize_and_resolve(
            &requested,
            &self.services,
            self.session_id,
            Some(transaction_id),
            self.limits.connect_timeout,
            &mut shutdown,
        )
        .await
        {
            Ok(addresses) => addresses,
            Err(error) => return response_for_error(error),
        };
        if let Some(response) = self
            .evaluate_http_policy(
                &requested,
                &addresses,
                transaction_id,
                Method::CONNECT.as_str(),
                target.authority(),
                request.headers(),
            )
            .await?
        {
            return Ok(response);
        }
        let (upstream, selected_address) =
            match connect_any(&addresses, self.limits.connect_timeout, &mut shutdown).await {
                Ok(connected) => connected,
                Err(error) => return response_for_error(error),
            };

        let on_upgrade = hyper::upgrade::on(&mut request);
        let handle = self
            .start_connect_tunnel(
                on_upgrade,
                upstream,
                selected_address,
                &target,
                transaction_id,
            )
            .await?;
        self.register_task(handle).await?;
        Ok(text_response(StatusCode::OK, ""))
    }

    async fn start_connect_tunnel(
        &self,
        on_upgrade: OnUpgrade,
        upstream: TcpStream,
        selected_address: SocketAddr,
        target: &ForwardTarget,
        transaction_id: TransactionId,
    ) -> Result<ConnectionTaskHandle, ProxyError> {
        let services = self.services.clone();
        let session_id = self.session_id;
        let tunnel_shutdown = self.shutdown.clone();
        let idle_timeout = self.limits.idle_timeout;
        let relay_limits = RelayLimits::new(
            self.limits.idle_timeout,
            self.limits.body_prefix_bytes,
            self.limits.read_timeout,
        );
        let handle = if let Some(interceptor) = self.services.tls_interceptor()
            && interceptor.should_intercept(target.host())
        {
            let (acceptor, cache_hit) = interceptor
                .downstream_acceptor(target.host(), None)
                .map_err(ProxyError::Tls)?;
            services
                .publish(AuditEnvelope {
                    context: audit_context(session_id, Some(transaction_id), &services),
                    event: AuditEvent::TlsCertificateGenerated {
                        hostname: target.host().to_string(),
                        cache_hit,
                    },
                })
                .await?;
            tokio::spawn(run_intercepted_tunnel(
                on_upgrade,
                upstream,
                acceptor,
                interceptor,
                target.clone(),
                selected_address,
                self.clone(),
                services,
                session_id,
                transaction_id,
                self.limits.connect_timeout,
                idle_timeout,
                tunnel_shutdown,
            ))
        } else {
            tokio::spawn(run_tunnel(
                on_upgrade,
                upstream,
                services,
                session_id,
                transaction_id,
                relay_limits,
                tunnel_shutdown,
            ))
        };
        Ok(handle)
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_http_policy(
        &self,
        requested: &RequestedTargetFacts,
        addresses: &[SocketAddr],
        transaction_id: TransactionId,
        method: &str,
        path: &str,
        headers: &http::HeaderMap,
    ) -> Result<Option<Response<ProxyBody>>, ProxyError> {
        let snapshot = self.services.decision_snapshot();
        let policy_headers = headers::policy_headers(headers);
        let mut first_denial = None;
        for address in addresses {
            let facts = HttpRequestFacts::new(
                ResolvedTargetFacts::new(requested.clone(), address.ip()),
                method,
                path,
                policy_headers.clone(),
            );
            self.services
                .publish_replay_facts(
                    audit_context(self.session_id, Some(transaction_id), &self.services),
                    ReplayFacts::HttpRequest(facts.clone()),
                )
                .await?;
            let decision = snapshot.policy().evaluate(PolicyFacts::HttpRequest(&facts));
            self.services
                .publish_decision(
                    audit_context(self.session_id, Some(transaction_id), &self.services),
                    decision.clone(),
                )
                .await?;
            if !snapshot.permits(&decision) && first_denial.is_none() {
                first_denial = Some(decision);
            }
        }
        if let Some(decision) = first_denial {
            record_action(
                self.session_id,
                Some(transaction_id),
                &self.services,
                decision,
            )
            .await?;
            return Ok(Some(text_response(StatusCode::FORBIDDEN, "forbidden\n")));
        }
        Ok(None)
    }

    async fn audit_request(
        &self,
        transaction_id: TransactionId,
        request: &Request<Incoming>,
    ) -> Result<(), ProxyError> {
        let method = request.method().as_str().to_owned();
        let target = request.uri().to_string();
        self.services.publish_http_event(
            self.session_id,
            transaction_id,
            method.clone(),
            target.clone(),
        );
        self.services
            .publish(AuditEnvelope {
                context: audit_context(self.session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpRequestObserved {
                    method,
                    target,
                    headers: headers::audit_headers(request.headers()),
                },
            })
            .await
    }

    async fn prepare_request_body(
        &self,
        request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Result<Request<ProxyBody>, Response<ProxyBody>>, ProxyError> {
        let (mut parts, body) = request.into_parts();
        match self.services.inspection_mode() {
            InspectionMode::Preflight => {
                let bytes = match collect_bounded(
                    body,
                    self.limits.body_prefix_bytes,
                    self.limits.read_timeout,
                )
                .await
                {
                    Ok(bytes) => bytes,
                    Err(CollectError::LimitExceeded { .. }) => {
                        return Ok(Err(text_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "request body exceeds preflight limit\n",
                        )));
                    }
                    Err(CollectError::Hyper(_)) => {
                        return Ok(Err(text_response(
                            StatusCode::BAD_REQUEST,
                            "request body stream failed\n",
                        )));
                    }
                    Err(CollectError::ReadTimedOut) => {
                        return Ok(Err(text_response(
                            StatusCode::REQUEST_TIMEOUT,
                            "request body read timed out\n",
                        )));
                    }
                };
                if !self
                    .inspect_preflight(transaction_id, Direction::HttpRequestBody, &bytes)
                    .await?
                {
                    return Ok(Err(block_page()));
                }
                let transformed = self
                    .transform_preflight_body(transaction_id, Direction::HttpRequestBody, bytes)
                    .await?;
                if transformed.replaced {
                    normalize_replaced_body_headers(&mut parts.headers);
                }
                set_content_length(&mut parts.headers, transformed.bytes.len());
                Ok(Ok(Request::from_parts(parts, full(transformed.bytes))))
            }
            InspectionMode::Streaming => {
                let body_may_change = self.services.hooks().may_mutate_request_body();
                let decoded_replacement_allowed =
                    !parts.headers.contains_key(header::CONTENT_ENCODING);
                if body_may_change && !decoded_replacement_allowed {
                    return Ok(Err(text_response(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "content-encoded body hooks require preflight mode\n",
                    )));
                }
                if body_may_change {
                    normalize_replaced_body_headers(&mut parts.headers);
                }
                remove_body_length_for_streaming_hooks(&mut parts.headers, body_may_change);
                let body = self
                    .start_streaming_inspection(
                        body,
                        transaction_id,
                        Direction::HttpRequestBody,
                        decoded_replacement_allowed,
                        body_may_change,
                    )
                    .await?;
                Ok(Ok(Request::from_parts(parts, body)))
            }
        }
    }

    async fn finish_response(
        &self,
        transaction_id: TransactionId,
        mut response: Response<Incoming>,
        requested: &RequestedTargetFacts,
        selected_address: SocketAddr,
        request_method: &Method,
    ) -> Result<Response<ProxyBody>, ProxyError> {
        if let Err(error) = headers::validate(response.headers(), self.limits.header_bytes) {
            return Ok(text_response(StatusCode::BAD_GATEWAY, &error.to_string()));
        }
        if !self
            .evaluate_http_response_policy(transaction_id, requested, selected_address, &response)
            .await?
        {
            return Ok(block_page());
        }
        self.apply_response_head_hooks(transaction_id, &mut response)
            .await?;
        if let Err(error) = headers::strip_hop_by_hop(response.headers_mut()) {
            return Ok(text_response(StatusCode::BAD_GATEWAY, &error.to_string()));
        }
        let (mut parts, body) = response.into_parts();
        if response_has_no_content(request_method, parts.status) {
            normalize_no_content_headers(request_method, parts.status, &mut parts.headers);
            return Ok(Response::from_parts(parts, full(bytes::Bytes::new())));
        }
        match self.services.inspection_mode() {
            InspectionMode::Preflight => {
                let bytes = match collect_bounded(
                    body,
                    self.limits.body_prefix_bytes,
                    self.limits.read_timeout,
                )
                .await
                {
                    Ok(bytes) => bytes,
                    Err(CollectError::ReadTimedOut) => {
                        return Ok(text_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            "upstream body read timed out\n",
                        ));
                    }
                    Err(error) => {
                        return Ok(text_response(StatusCode::BAD_GATEWAY, &error.to_string()));
                    }
                };
                if !self
                    .inspect_preflight(transaction_id, Direction::HttpResponseBody, &bytes)
                    .await?
                {
                    return Ok(block_page());
                }
                let transformed = self
                    .transform_preflight_body(transaction_id, Direction::HttpResponseBody, bytes)
                    .await?;
                if transformed.replaced {
                    normalize_replaced_body_headers(&mut parts.headers);
                }
                set_content_length(&mut parts.headers, transformed.bytes.len());
                Ok(Response::from_parts(parts, full(transformed.bytes)))
            }
            InspectionMode::Streaming => {
                let body_may_change = self.services.hooks().may_mutate_response_body();
                let decoded_replacement_allowed =
                    !parts.headers.contains_key(header::CONTENT_ENCODING);
                if body_may_change && !decoded_replacement_allowed {
                    return Ok(text_response(
                        StatusCode::BAD_GATEWAY,
                        "content-encoded response hooks require preflight mode\n",
                    ));
                }
                if body_may_change {
                    normalize_replaced_body_headers(&mut parts.headers);
                }
                remove_body_length_for_streaming_hooks(&mut parts.headers, body_may_change);
                let body = self
                    .start_streaming_inspection(
                        body,
                        transaction_id,
                        Direction::HttpResponseBody,
                        decoded_replacement_allowed,
                        body_may_change,
                    )
                    .await?;
                Ok(Response::from_parts(parts, body))
            }
        }
    }

    async fn evaluate_http_response_policy(
        &self,
        transaction_id: TransactionId,
        requested: &RequestedTargetFacts,
        selected_address: SocketAddr,
        response: &Response<Incoming>,
    ) -> Result<bool, ProxyError> {
        let snapshot = self.services.decision_snapshot();
        let facts = HttpResponseFacts::new(
            ResolvedTargetFacts::new(requested.clone(), selected_address.ip()),
            response.status().as_u16(),
            headers::policy_headers(response.headers()),
        );
        self.services
            .publish_replay_facts(
                audit_context(self.session_id, Some(transaction_id), &self.services),
                ReplayFacts::HttpResponse(facts.clone()),
            )
            .await?;
        let decision = snapshot
            .policy()
            .evaluate(PolicyFacts::HttpResponse(&facts));
        self.services
            .publish_decision(
                audit_context(self.session_id, Some(transaction_id), &self.services),
                decision.clone(),
            )
            .await?;
        if snapshot.permits(&decision) {
            return Ok(true);
        }
        record_action(
            self.session_id,
            Some(transaction_id),
            &self.services,
            decision,
        )
        .await?;
        Ok(false)
    }

    async fn inspect_preflight(
        &self,
        transaction_id: TransactionId,
        direction: Direction,
        bytes: &[u8],
    ) -> Result<bool, ProxyError> {
        let mut inspection = FlowInspector::new(
            self.services.clone(),
            self.session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        );
        inspection.permits(direction, bytes).await
    }

    async fn transform_preflight_body(
        &self,
        transaction_id: TransactionId,
        direction: Direction,
        bytes: bytes::Bytes,
    ) -> Result<BodyTransform, ProxyError> {
        let inspection = FlowInspector::new(
            self.services.clone(),
            self.session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        );
        inspection
            .transform_http_body(direction, bytes, self.limits.body_prefix_bytes, true)
            .await
    }

    async fn apply_request_head_hooks(
        &self,
        transaction_id: TransactionId,
        request: &mut Request<Incoming>,
    ) -> Result<(), ProxyError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpRequestHead {
            method: request.method().clone(),
            uri: request.uri().clone(),
            headers: request.headers().clone(),
        };
        let result = self.services.hooks().request_head(&input).await;
        let context = audit_context(self.session_id, Some(transaction_id), &self.services);
        self.services
            .publish_hook_outcome(context, "http-request-head", result.is_ok())
            .await?;
        let plan = result.map_err(ProxyError::Hook)?;
        apply_head_mutation(request.headers_mut(), &plan).map_err(ProxyError::HookMutation)?;
        match self
            .services
            .interactive_decision(context, InterceptStage::HttpRequestHead)
            .await?
        {
            Some(InteractiveDecision::EditHeaders(plan)) => {
                apply_head_mutation(request.headers_mut(), &plan).map_err(ProxyError::HookMutation)
            }
            Some(InteractiveDecision::Reject) => Err(ProxyError::InteractiveRejected),
            Some(
                InteractiveDecision::Continue
                | InteractiveDecision::ReplaceBody(_)
                | InteractiveDecision::CancelModification,
            )
            | None => Ok(()),
        }
    }

    async fn apply_response_head_hooks(
        &self,
        transaction_id: TransactionId,
        response: &mut Response<Incoming>,
    ) -> Result<(), ProxyError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpResponseHead {
            status: response.status(),
            headers: response.headers().clone(),
        };
        let result = self.services.hooks().response_head(&input).await;
        let context = audit_context(self.session_id, Some(transaction_id), &self.services);
        self.services
            .publish_hook_outcome(context, "http-response-head", result.is_ok())
            .await?;
        let plan = result.map_err(ProxyError::Hook)?;
        apply_head_mutation(response.headers_mut(), &plan).map_err(ProxyError::HookMutation)?;
        match self
            .services
            .interactive_decision(context, InterceptStage::HttpResponseHead)
            .await?
        {
            Some(InteractiveDecision::EditHeaders(plan)) => {
                apply_head_mutation(response.headers_mut(), &plan).map_err(ProxyError::HookMutation)
            }
            Some(InteractiveDecision::Reject) => Err(ProxyError::InteractiveRejected),
            Some(
                InteractiveDecision::Continue
                | InteractiveDecision::ReplaceBody(_)
                | InteractiveDecision::CancelModification,
            )
            | None => Ok(()),
        }
    }

    async fn start_streaming_inspection(
        &self,
        body: Incoming,
        transaction_id: TransactionId,
        direction: Direction,
        decoded_replacement_allowed: bool,
        body_may_change: bool,
    ) -> Result<ProxyBody, ProxyError> {
        let (sender, inspected) = channel(8);
        let inspection = FlowInspector::new(
            self.services.clone(),
            self.session_id,
            Some(transaction_id),
            Protocol::Http,
            self.limits.body_prefix_bytes,
        );
        let handle = tokio::spawn(pump_inspected_body(
            body,
            sender,
            inspection,
            BodyPumpConfig {
                direction,
                maximum_inspected_bytes: self.limits.body_prefix_bytes,
                read_timeout: self.limits.read_timeout,
                decoded_replacement_allowed,
                body_may_change,
                shutdown: self.shutdown.clone(),
            },
        ));
        self.register_task(handle).await?;
        Ok(inspected)
    }

    async fn audit_response(
        &self,
        transaction_id: TransactionId,
        status: u16,
        headers: std::collections::BTreeMap<String, Vec<String>>,
    ) -> Result<(), ProxyError> {
        self.services
            .publish(AuditEnvelope {
                context: audit_context(self.session_id, Some(transaction_id), &self.services),
                event: AuditEvent::HttpResponseObserved { status, headers },
            })
            .await
    }

    async fn establish_http_sender(
        &self,
        upstream: TcpStream,
    ) -> Result<http1::SendRequest<ProxyBody>, ProxyError> {
        let handshake = timeout(
            self.limits.connect_timeout,
            http1::handshake::<_, ProxyBody>(TokioIo::new(upstream)),
        )
        .await;
        let (sender, connection) = match handshake {
            Ok(Ok(parts)) => parts,
            Ok(Err(source)) => {
                return Err(ProxyError::UpstreamHttp {
                    stage: "handshake",
                    source,
                });
            }
            Err(_) => return Err(ProxyError::UpstreamResponseTimedOut),
        };
        let mut connection_shutdown = self.shutdown.clone();
        let connection_task = tokio::spawn(async move {
            tokio::select! {
                () = connection_shutdown.cancelled() => Ok(()),
                result = connection => result.map_err(|source| ProxyError::UpstreamHttp {
                    stage: "connection",
                    source,
                }),
            }
        });
        self.register_task(connection_task).await?;
        Ok(sender)
    }

    async fn send_upstream_request(
        &self,
        upstream: TcpStream,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, ProxyError> {
        let mut sender = self.establish_http_sender(upstream).await?;
        match timeout(self.limits.idle_timeout, sender.send_request(request)).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(source)) => Err(ProxyError::UpstreamHttp {
                stage: "request",
                source,
            }),
            Err(_) => Err(ProxyError::UpstreamResponseTimedOut),
        }
    }

    fn connect_port_denial(
        &self,
        port: freja_domain::Port,
        snapshot: &crate::runtime::DecisionSnapshot,
    ) -> Decision {
        let action = EnforcementAction::HttpReject(HttpReject::Forbidden);
        Decision {
            trace: DecisionTrace {
                policy_generation: snapshot.policy().generation(),
                evaluated_stage: PolicyStage::HttpRequest,
                matched_rule: Some(self.connect_port_rule.clone()),
                match_reasons: vec![MatchReason {
                    criterion: "connect-port-allowlist".to_owned(),
                    observed: port.to_string(),
                }],
                final_action: action.kind(),
            },
            action,
        }
    }

    async fn register_task(&self, handle: ConnectionTaskHandle) -> Result<(), ProxyError> {
        if let Err(error) = self.task_sender.send(handle).await {
            error.0.abort();
            return Err(ProxyError::TunnelRegistration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterceptedProtocol {
    Http1,
    Http2,
}

impl InterceptedProtocol {
    const fn http_version(self) -> Version {
        match self {
            Self::Http1 => Version::HTTP_11,
            Self::Http2 => Version::HTTP_2,
        }
    }
}

enum InterceptedUpstreamSender {
    Http1(http1::SendRequest<ProxyBody>),
    Http2(http2::SendRequest<ProxyBody>),
}

impl InterceptedUpstreamSender {
    async fn send_request(
        &mut self,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, ProxyError> {
        match self {
            Self::Http1(sender) => {
                sender
                    .ready()
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/1 readiness",
                        source,
                    })?;
                sender
                    .send_request(request)
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/1 request",
                        source,
                    })
            }
            Self::Http2(sender) => {
                sender
                    .ready()
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/2 readiness",
                        source,
                    })?;
                sender
                    .send_request(request)
                    .await
                    .map_err(|source| ProxyError::UpstreamHttp {
                        stage: "intercepted HTTP/2 request",
                        source,
                    })
            }
        }
    }
}

fn regenerate_host(headers: &mut http::HeaderMap, authority: &str) -> bool {
    let Ok(host) = HeaderValue::from_str(authority) else {
        return false;
    };
    headers.insert(header::HOST, host);
    true
}

fn intercepted_upstream_uri(
    protocol: InterceptedProtocol,
    authority: &str,
    path_and_query: &str,
) -> Option<http::Uri> {
    match protocol {
        InterceptedProtocol::Http1 => path_and_query.parse().ok(),
        InterceptedProtocol::Http2 => http::Uri::builder()
            .scheme("https")
            .authority(authority)
            .path_and_query(path_and_query)
            .build()
            .ok(),
    }
}

#[derive(Clone, Default)]
struct PlaintextCounters {
    client_to_upstream: Arc<AtomicU64>,
    upstream_to_client: Arc<AtomicU64>,
}

impl PlaintextCounters {
    fn stats(&self) -> RelayStats {
        RelayStats {
            client_to_upstream_bytes: self.client_to_upstream.load(Ordering::Relaxed),
            upstream_to_client_bytes: self.upstream_to_client.load(Ordering::Relaxed),
        }
    }
}

struct ReadCountingIo<T> {
    inner: T,
    bytes: Arc<AtomicU64>,
}

impl<T> ReadCountingIo<T> {
    fn new(inner: T, bytes: Arc<AtomicU64>) -> Self {
        Self { inner, bytes }
    }

    fn record(&self, count: usize) {
        let count = u64::try_from(count).unwrap_or(u64::MAX);
        let _update = self
            .bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(count))
            });
    }
}

impl<T> AsyncRead for ReadCountingIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let previous = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            self.record(buffer.filled().len().saturating_sub(previous));
        }
        result
    }
}

impl<T> AsyncWrite for ReadCountingIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

struct BodyPumpConfig {
    direction: Direction,
    maximum_inspected_bytes: usize,
    read_timeout: std::time::Duration,
    decoded_replacement_allowed: bool,
    body_may_change: bool,
    shutdown: ShutdownSignal,
}

async fn pump_inspected_body(
    mut body: Incoming,
    sender: mpsc::Sender<BodyFrame>,
    mut inspection: FlowInspector,
    config: BodyPumpConfig,
) -> Result<(), ProxyError> {
    let BodyPumpConfig {
        direction,
        maximum_inspected_bytes,
        read_timeout,
        decoded_replacement_allowed,
        body_may_change,
        mut shutdown,
    } = config;
    let mut inspected_bytes = 0_usize;
    loop {
        let frame = tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            () = tokio::time::sleep(read_timeout) => {
                send_body_frame(&sender, Err(BodyError::ReadTimedOut), &mut shutdown).await;
                return Ok(());
            }
            frame = body.frame() => frame,
        };
        let Some(frame) = frame else {
            return Ok(());
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(source) => {
                send_body_frame(&sender, Err(BodyError::Hyper(source)), &mut shutdown).await;
                return Ok(());
            }
        };
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(frame) => {
                if body_may_change {
                    continue;
                }
                if !send_body_frame(&sender, Ok(frame), &mut shutdown).await {
                    return Ok(());
                }
                continue;
            }
        };
        let remaining = maximum_inspected_bytes.saturating_sub(inspected_bytes);
        let inspect_count = remaining.min(data.len());
        if inspect_count > 0 {
            match inspection.permits(direction, &data[..inspect_count]).await {
                Ok(true) => {}
                Ok(false) => {
                    send_body_frame(&sender, Err(BodyError::InspectionBlocked), &mut shutdown)
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    send_body_frame(
                        &sender,
                        Err(BodyError::Inspection(Box::new(error))),
                        &mut shutdown,
                    )
                    .await;
                    return Ok(());
                }
            }
            inspected_bytes = inspected_bytes.saturating_add(inspect_count);
        }
        let transformed = match inspection
            .transform_http_body(
                direction,
                data,
                maximum_inspected_bytes,
                decoded_replacement_allowed,
            )
            .await
        {
            Ok(data) => data,
            Err(error) => {
                send_body_frame(
                    &sender,
                    Err(BodyError::Inspection(Box::new(error))),
                    &mut shutdown,
                )
                .await;
                return Ok(());
            }
        };
        if !send_body_frame(
            &sender,
            Ok(hyper::body::Frame::data(transformed.bytes)),
            &mut shutdown,
        )
        .await
        {
            return Ok(());
        }
    }
}

async fn send_body_frame(
    sender: &mpsc::Sender<BodyFrame>,
    frame: BodyFrame,
    shutdown: &mut ShutdownSignal,
) -> bool {
    tokio::select! {
        () = shutdown.cancelled() => false,
        result = sender.send(frame) => result.is_ok(),
    }
}

fn set_content_length(headers: &mut http::HeaderMap, length: usize) {
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
}

fn remove_body_length_for_streaming_hooks(headers: &mut http::HeaderMap, body_may_change: bool) {
    if body_may_change {
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::TRANSFER_ENCODING);
    }
}

fn response_has_no_content(request_method: &Method, status: StatusCode) -> bool {
    *request_method == Method::HEAD
        || status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
}

fn normalize_no_content_headers(
    request_method: &Method,
    status: StatusCode,
    headers: &mut http::HeaderMap,
) {
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    if status.is_informational() || status == StatusCode::NO_CONTENT {
        headers.remove(header::CONTENT_LENGTH);
    } else if status == StatusCode::RESET_CONTENT {
        set_content_length(headers, 0);
    } else {
        debug_assert!(*request_method == Method::HEAD || status == StatusCode::NOT_MODIFIED);
    }
}

fn block_page() -> Response<ProxyBody> {
    text_response(
        StatusCode::FORBIDDEN,
        "<!doctype html><title>Blocked by Freja</title><h1>Request blocked</h1>\n",
    )
}

async fn run_tunnel(
    on_upgrade: OnUpgrade,
    upstream: tokio::net::TcpStream,
    services: DataPlaneServices,
    session_id: SessionId,
    transaction_id: TransactionId,
    relay_limits: RelayLimits,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError> {
    let upgraded = tokio::select! {
        () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
        result = on_upgrade => result.map_err(ProxyError::HttpUpgrade)?,
    };
    let inspection = FlowInspector::new(
        services.clone(),
        session_id,
        Some(transaction_id),
        Protocol::Tcp,
        relay_limits.inspection_bytes(),
    );
    let result = relay(
        TokioIo::new(upgraded),
        upstream,
        relay_limits,
        shutdown,
        Some(inspection),
    )
    .await;
    let (stats, outcome) = match &result {
        Ok(relay) => (relay.stats, tunnel_outcome(relay.termination)),
        Err(error) => (RelayStats::default(), tunnel_error_outcome(error)),
    };
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, Some(transaction_id), &services),
            event: AuditEvent::TunnelClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome: outcome.to_owned(),
            },
        })
        .await?;
    result.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn run_intercepted_tunnel(
    on_upgrade: OnUpgrade,
    upstream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    interceptor: std::sync::Arc<crate::TlsInterceptor>,
    target: ForwardTarget,
    selected_address: SocketAddr,
    service: HttpService,
    services: DataPlaneServices,
    session_id: SessionId,
    transaction_id: TransactionId,
    connect_timeout: std::time::Duration,
    idle_timeout: std::time::Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError> {
    let counters = PlaintextCounters::default();
    let active_counters = counters.clone();
    let result = Box::pin(async {
        let upgraded = tokio::select! {
            () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
            result = on_upgrade => result.map_err(ProxyError::HttpUpgrade)?,
        };
        let downstream = tokio::select! {
            () = shutdown.cancelled() => return Err(ProxyError::Shutdown),
            result = timeout(idle_timeout, acceptor.accept(TokioIo::new(upgraded))) => {
                match result {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(source)) => {
                        return Err(ProxyError::Tls(crate::TlsError::DownstreamHandshake(source)));
                    }
                    Err(_) => {
                        return Err(ProxyError::Tls(
                            crate::TlsError::DownstreamHandshakeTimedOut,
                        ));
                    }
                }
            }
        };
        let downstream_alpn = downstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let upstream = match timeout(
            connect_timeout,
            interceptor.connect_upstream(upstream, target.host(), downstream_alpn.as_deref()),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(ProxyError::Tls(error)),
            Err(_) => return Err(ProxyError::UpstreamResponseTimedOut),
        };
        validate_intercepted_alpn(
            downstream_alpn.as_deref(),
            upstream.get_ref().1.alpn_protocol(),
        )?;
        let protocol = match downstream_alpn.as_deref() {
            Some(b"h2") => InterceptedProtocol::Http2,
            Some(b"http/1.1") | None => InterceptedProtocol::Http1,
            Some(protocol) => {
                return Err(ProxyError::Tls(
                    crate::TlsError::UnsupportedApplicationProtocol {
                        protocol: String::from_utf8_lossy(protocol).into_owned(),
                    },
                ));
            }
        };
        services
            .publish(AuditEnvelope {
                context: audit_context(session_id, Some(transaction_id), &services),
                event: AuditEvent::TlsInterceptionEstablished {
                    hostname: target.host().to_string(),
                    alpn: downstream_alpn
                        .as_deref()
                        .map(|value| String::from_utf8_lossy(value).into_owned()),
                },
            })
            .await?;
        let downstream =
            ReadCountingIo::new(downstream, Arc::clone(&active_counters.client_to_upstream));
        let upstream =
            ReadCountingIo::new(upstream, Arc::clone(&active_counters.upstream_to_client));
        serve_intercepted_http(
            protocol,
            downstream,
            upstream,
            service,
            target,
            selected_address,
            idle_timeout,
            shutdown,
        )
        .await
    })
    .await;
    let stats = counters.stats();
    let outcome = match &result {
        Ok(()) => "completed",
        Err(error) => intercepted_tunnel_error_outcome(error),
    };
    services
        .publish(AuditEnvelope {
            context: audit_context(session_id, Some(transaction_id), &services),
            event: AuditEvent::TunnelClosed {
                client_to_upstream_bytes: stats.client_to_upstream_bytes,
                upstream_to_client_bytes: stats.upstream_to_client_bytes,
                outcome: outcome.to_owned(),
            },
        })
        .await?;
    result
}

const fn intercepted_tunnel_error_outcome(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::Tls(crate::TlsError::DownstreamHandshake(_)) => "tls-client-rejected",
        ProxyError::Tls(crate::TlsError::DownstreamHandshakeTimedOut) => "tls-client-timeout",
        ProxyError::Tls(crate::TlsError::UpstreamHandshake { .. }) => "tls-upstream-rejected",
        ProxyError::Tls(
            crate::TlsError::ApplicationProtocolMismatch { .. }
            | crate::TlsError::UnsupportedApplicationProtocol { .. },
        ) => "tls-alpn-rejected",
        ProxyError::UpstreamResponseTimedOut => "tls-upstream-timeout",
        other => tunnel_error_outcome(other),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_intercepted_http<Downstream, Upstream>(
    protocol: InterceptedProtocol,
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    idle_timeout: std::time::Duration,
    shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match protocol {
        InterceptedProtocol::Http1 => {
            serve_intercepted_http1(
                downstream,
                upstream,
                service,
                target,
                selected_address,
                shutdown,
            )
            .await
        }
        InterceptedProtocol::Http2 => {
            serve_intercepted_http2(
                downstream,
                upstream,
                service,
                target,
                selected_address,
                idle_timeout,
                shutdown,
            )
            .await
        }
    }
}

async fn serve_intercepted_http1<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = service.limits;
    let (sender, upstream_connection) = http1::handshake::<_, ProxyBody>(TokioIo::new(upstream))
        .await
        .map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/1 handshake",
            source,
        })?;
    let sender = Arc::new(Mutex::new(InterceptedUpstreamSender::Http1(sender)));
    let request_service = service_fn(move |request| {
        let service = service.clone();
        let target = target.clone();
        let sender = Arc::clone(&sender);
        async move {
            service
                .handle_intercepted(
                    request,
                    &target,
                    selected_address,
                    InterceptedProtocol::Http1,
                    &sender,
                )
                .await
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.read_timeout)
        .max_buf_size(limits.header_bytes.max(8 * 1_024));
    let downstream_connection = builder.serve_connection(TokioIo::new(downstream), request_service);
    tokio::pin!(downstream_connection);
    tokio::pin!(upstream_connection);
    tokio::select! {
        () = shutdown.cancelled() => Err(ProxyError::Shutdown),
        result = &mut downstream_connection => result.map_err(ProxyError::HttpConnection),
        result = &mut upstream_connection => result.map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/1 connection",
            source,
        }),
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_intercepted_http2<Downstream, Upstream>(
    downstream: Downstream,
    upstream: Upstream,
    service: HttpService,
    target: ForwardTarget,
    selected_address: SocketAddr,
    idle_timeout: std::time::Duration,
    mut shutdown: ShutdownSignal,
) -> Result<(), ProxyError>
where
    Downstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Upstream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let limits = service.limits;
    let maximum_headers = u32::try_from(limits.header_bytes).unwrap_or(u32::MAX);
    let maximum_streams = u32::try_from(limits.connections).unwrap_or(u32::MAX);
    let mut client_builder = http2::Builder::new(TokioExecutor::new());
    client_builder
        .max_header_list_size(maximum_headers)
        .max_concurrent_streams(maximum_streams);
    let (sender, upstream_connection) = client_builder
        .handshake::<_, ProxyBody>(TokioIo::new(upstream))
        .await
        .map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/2 handshake",
            source,
        })?;
    let sender = Arc::new(Mutex::new(InterceptedUpstreamSender::Http2(sender)));
    let request_service = service_fn(move |request| {
        let service = service.clone();
        let target = target.clone();
        let sender = Arc::clone(&sender);
        async move {
            service
                .handle_intercepted(
                    request,
                    &target,
                    selected_address,
                    InterceptedProtocol::Http2,
                    &sender,
                )
                .await
        }
    });
    let mut server_builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    server_builder
        .timer(TokioTimer::new())
        .max_header_list_size(maximum_headers)
        .max_concurrent_streams(maximum_streams)
        .keep_alive_interval(idle_timeout)
        .keep_alive_timeout(idle_timeout);
    let downstream_connection =
        server_builder.serve_connection(TokioIo::new(downstream), request_service);
    tokio::pin!(downstream_connection);
    tokio::pin!(upstream_connection);
    tokio::select! {
        () = shutdown.cancelled() => Err(ProxyError::Shutdown),
        result = &mut downstream_connection => result.map_err(ProxyError::HttpConnection),
        result = &mut upstream_connection => result.map_err(|source| ProxyError::UpstreamHttp {
            stage: "intercepted HTTP/2 connection",
            source,
        }),
    }
}

fn validate_intercepted_alpn(
    downstream: Option<&[u8]>,
    upstream: Option<&[u8]>,
) -> Result<(), ProxyError> {
    let compatible = matches!(
        (downstream, upstream),
        (Some(b"h2"), Some(b"h2")) | (Some(b"http/1.1") | None, Some(b"http/1.1") | None)
    );
    if compatible {
        return Ok(());
    }
    Err(ProxyError::Tls(
        crate::TlsError::ApplicationProtocolMismatch {
            downstream: downstream.map(|value| String::from_utf8_lossy(value).into_owned()),
            upstream: upstream.map(|value| String::from_utf8_lossy(value).into_owned()),
        },
    ))
}

fn response_for_error(error: ProxyError) -> Result<Response<ProxyBody>, ProxyError> {
    match error {
        ProxyError::PolicyDenied { .. } => Ok(text_response(StatusCode::FORBIDDEN, "forbidden\n")),
        ProxyError::DetourLoop { .. } => Ok(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid TCP detour policy\n",
        )),
        ProxyError::ConnectTimedOut { .. }
        | ProxyError::DnsTimedOut { .. }
        | ProxyError::UpstreamResponseTimedOut => Ok(text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream timeout\n",
        )),
        ProxyError::Dns { .. }
        | ProxyError::NoResolvedAddresses { .. }
        | ProxyError::ConnectFailed { .. }
        | ProxyError::UpstreamHttp { .. }
        | ProxyError::Tls(_) => Ok(text_response(StatusCode::BAD_GATEWAY, "bad gateway\n")),
        ProxyError::Hook(_) | ProxyError::HookMutation(_) => Ok(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hook execution failed\n",
        )),
        ProxyError::InteractiveRejected => Ok(text_response(
            StatusCode::FORBIDDEN,
            "rejected by operator\n",
        )),
        ProxyError::Interactive(_) => Ok(text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "interactive interception failed\n",
        )),
        other => Err(other),
    }
}

fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn authenticate_proxy_request(
    headers: &http::HeaderMap,
    authentication: &ProxyAuthentication,
) -> bool {
    let mut values = headers.get_all(header::PROXY_AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return false;
    }
    let Ok(mut credential) = STANDARD.decode(encoded) else {
        return false;
    };
    let candidate = Sha256::digest(&credential);
    credential.fill(0);
    constant_time_equal(
        candidate.as_slice(),
        authentication.credential_hash().as_bytes(),
    )
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn proxy_authentication_required(authentication: &ProxyAuthentication) -> Response<ProxyBody> {
    let mut response = text_response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    if let Ok(challenge) = HeaderValue::from_str(&format!(
        "Basic realm=\"{}\", charset=\"UTF-8\"",
        authentication.realm()
    )) {
        response
            .headers_mut()
            .insert(header::PROXY_AUTHENTICATE, challenge);
    }
    response
}

const fn tunnel_outcome(termination: RelayTermination) -> &'static str {
    match termination {
        RelayTermination::Completed => "completed",
        RelayTermination::IdleTimeout => "idle-timeout",
        RelayTermination::Shutdown => "shutdown",
        RelayTermination::InspectionBlocked => "inspection-blocked",
    }
}

const fn tunnel_error_outcome(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::RelayRead { .. } | ProxyError::RelayWrite { .. } => "relay-failure",
        ProxyError::Shutdown => "shutdown",
        _ => "tunnel-failure",
    }
}
