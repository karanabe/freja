use std::{net::SocketAddr, sync::Arc};

use freja_domain::{
    Direction, EvaluationTarget, HttpRequestFacts, HttpResponseFacts, InspectionMode, Protocol,
    ReplayFacts, RequestedTargetFacts, ResolvedTargetFacts, TransactionId,
};
use freja_policy::{PolicyFacts, hook::normalize_replaced_body_headers};
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use hyper::{body::Incoming, client::conn::http1};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpStream, sync::Mutex, time::timeout};

use super::{
    CollectError, ForwardTarget, HttpService, ProxyBody, ProxyError, audit_context,
    authorize_and_resolve,
    body::{
        block_page, normalize_no_content_headers, remove_body_length_for_streaming_hooks,
        response_has_no_content, set_content_length,
    },
    collect_bounded, connect_any, full, headers,
    intercept::{InterceptedProtocol, InterceptedUpstreamSender},
    record_action,
    response::{response_for_error, text_response},
};
use crate::http::wire::ResponseCaptureIo;

impl HttpService {
    pub(super) async fn handle_intercepted(
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
        if self.services.publishes_events() {
            self.services.publish_http_response_event(
                self.session_id,
                transaction_id,
                response.status().as_u16(),
                format!("{:?}", response.version()),
                headers::presentation_headers(response.headers()),
            );
        }
        self.audit_response(
            transaction_id,
            response.status().as_u16(),
            headers::audit_headers(response.headers()),
        )
        .await?;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn forward_intercepted(
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
        let repeat_uri = canonical_intercepted_uri(target.authority(), &path_and_query);
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
        let resolved = ResolvedTargetFacts::new(requested.clone(), selected_address.ip());
        let request = match self
            .prepare_request_body(request, transaction_id, repeat_uri, &resolved)
            .await?
        {
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

    #[allow(clippy::too_many_lines)]
    pub(super) async fn forward(
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
        let repeat_uri = Some(request.uri().clone());
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
        let resolved = ResolvedTargetFacts::new(requested.clone(), selected_address.ip());
        let request = match self
            .prepare_request_body(request, transaction_id, repeat_uri, &resolved)
            .await?
        {
            Ok(request) => request,
            Err(response) => return Ok(response),
        };
        let response = match self
            .send_upstream_request(upstream, request, transaction_id)
            .await
        {
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
    pub(super) async fn evaluate_http_policy(
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
            let (decision, definition) = snapshot
                .policy()
                .evaluate_with_definition(PolicyFacts::HttpRequest(&facts));
            self.services
                .publish_decision(
                    audit_context(self.session_id, Some(transaction_id), &self.services),
                    decision.clone(),
                    (definition, snapshot.enforcement()),
                    EvaluationTarget::Resolved(facts.target().clone()),
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

    pub(super) async fn finish_response(
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
        let inspection_target = ResolvedTargetFacts::new(requested.clone(), selected_address.ip());
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
                    .inspect_preflight(
                        transaction_id,
                        Direction::HttpResponseBody,
                        &bytes,
                        &inspection_target,
                    )
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
                        &inspection_target,
                    )
                    .await?;
                Ok(Response::from_parts(parts, body))
            }
        }
    }

    pub(super) async fn evaluate_http_response_policy(
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
        let (decision, definition) = snapshot
            .policy()
            .evaluate_with_definition(PolicyFacts::HttpResponse(&facts));
        self.services
            .publish_decision(
                audit_context(self.session_id, Some(transaction_id), &self.services),
                decision.clone(),
                (definition, snapshot.enforcement()),
                EvaluationTarget::Resolved(facts.target().clone()),
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
    pub(super) async fn establish_http_sender<Stream>(
        &self,
        upstream: Stream,
    ) -> Result<http1::SendRequest<ProxyBody>, ProxyError>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
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

    pub(super) async fn send_upstream_request(
        &self,
        upstream: TcpStream,
        request: Request<ProxyBody>,
        transaction_id: TransactionId,
    ) -> Result<Response<Incoming>, ProxyError> {
        let request_was_head = request.method() == Method::HEAD;
        if let Some(capture) = self.services.ui_capture_settings() {
            let upstream = ResponseCaptureIo::new(
                upstream,
                self.services.clone(),
                self.session_id,
                transaction_id,
                self.limits.header_bytes,
                capture.content_bytes(),
                request_was_head,
                false,
            );
            return self.send_request_on(upstream, request).await;
        }
        self.send_request_on(upstream, request).await
    }

    async fn send_request_on<Stream>(
        &self,
        upstream: Stream,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, ProxyError>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
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

fn canonical_intercepted_uri(authority: &str, path_and_query: &str) -> Option<http::Uri> {
    http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .ok()
}
