use freja_domain::{Direction, HookMode, InspectionMode, Protocol, TransactionId};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use tokio::sync::mpsc;

use super::{
    BodyError, BodyFrame, BodyTransform, CollectError, FlowInspector, HttpService, ProxyBody,
    ProxyError, ShutdownSignal, channel, collect_bounded, full, response::text_response,
};
use freja_policy::hook::{
    BodyMutationPlan, HttpRequestSnapshot, InteractiveDecision, WireBody, apply_body_mutation,
    apply_head_mutation, apply_http_mutation, normalize_replaced_body_headers,
};

impl HttpService {
    pub(super) async fn prepare_request_body(
        &self,
        request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Result<Request<ProxyBody>, Response<ProxyBody>>, ProxyError> {
        if self.services.hooks().mode() == HookMode::Interactive {
            return self
                .prepare_interactive_request(request, transaction_id)
                .await;
        }
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

    async fn prepare_interactive_request(
        &self,
        request: Request<Incoming>,
        transaction_id: TransactionId,
    ) -> Result<Result<Request<ProxyBody>, Response<ProxyBody>>, ProxyError> {
        let (mut parts, body) = request.into_parts();
        let original = match collect_bounded(
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
                    "request body exceeds interactive limit\n",
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
            .inspect_preflight(transaction_id, Direction::HttpRequestBody, &original)
            .await?
        {
            return Ok(Err(block_page()));
        }
        let transformed = self
            .transform_preflight_body(transaction_id, Direction::HttpRequestBody, original)
            .await?;
        let mut body = transformed.bytes;
        if transformed.replaced {
            normalize_replaced_body_headers(&mut parts.headers);
        }
        let context = super::audit_context(self.session_id, Some(transaction_id), &self.services);
        let snapshot = HttpRequestSnapshot {
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            version: parts.version,
            headers: parts.headers.clone(),
            body: WireBody::new(body.clone()),
            maximum_head_bytes: self.limits.header_bytes,
            maximum_body_bytes: self.limits.body_prefix_bytes,
        };
        match self
            .services
            .interactive_http_request(context, transaction_id, snapshot)
            .await?
        {
            Some(InteractiveDecision::EditHeaders(plan)) => {
                apply_head_mutation(&mut parts.headers, &plan).map_err(ProxyError::HookMutation)?;
            }
            Some(InteractiveDecision::ReplaceBody(replacement)) => {
                body = apply_body_mutation(
                    &WireBody::new(body),
                    &BodyMutationPlan::Replace(replacement),
                    self.limits.body_prefix_bytes,
                )
                .map_err(ProxyError::HookMutation)?;
                normalize_replaced_body_headers(&mut parts.headers);
            }
            Some(InteractiveDecision::ModifyRequest(plan)) => {
                body = apply_http_mutation(
                    &mut parts.headers,
                    &WireBody::new(body),
                    &plan.head,
                    &plan.body,
                    self.limits.body_prefix_bytes,
                )
                .map_err(ProxyError::HookMutation)?;
            }
            Some(InteractiveDecision::Reject) => {
                return Err(ProxyError::InteractiveRejected);
            }
            Some(InteractiveDecision::Continue | InteractiveDecision::CancelModification)
            | None => {}
        }
        set_content_length(&mut parts.headers, body.len());
        Ok(Ok(Request::from_parts(parts, full(body))))
    }

    pub(super) async fn inspect_preflight(
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

    pub(super) async fn transform_preflight_body(
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

    pub(super) async fn start_streaming_inspection(
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

pub(super) fn set_content_length(headers: &mut http::HeaderMap, length: usize) {
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(header::CONTENT_LENGTH, value);
    }
}

pub(super) fn remove_body_length_for_streaming_hooks(
    headers: &mut http::HeaderMap,
    body_may_change: bool,
) {
    if body_may_change {
        headers.remove(header::CONTENT_LENGTH);
        headers.remove(header::TRANSFER_ENCODING);
    }
}

pub(super) fn response_has_no_content(request_method: &Method, status: StatusCode) -> bool {
    *request_method == Method::HEAD
        || status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::RESET_CONTENT | StatusCode::NOT_MODIFIED
        )
}

pub(super) fn normalize_no_content_headers(
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

pub(super) fn block_page() -> Response<ProxyBody> {
    text_response(
        StatusCode::FORBIDDEN,
        "<!doctype html><title>Blocked by Freja</title><h1>Request blocked</h1>\n",
    )
}
