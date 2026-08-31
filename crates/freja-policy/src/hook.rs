//! In-process typed hooks and bounded interactive interception.

use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use bytes::Bytes;
use freja_domain::{HookMode, SessionId, TransactionId};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use tokio::sync::{Semaphore, mpsc, oneshot};

/// Boxed async result returned by a registered hook without an async-trait dependency.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HookError>> + Send + 'a>>;

/// Hook-supplied failure with a stable, secret-free message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookError {
    message: String,
}

impl HookError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for HookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for HookError {}

/// A request head detached from any server/runtime representation.
#[derive(Debug, Clone)]
pub struct HttpRequestHead {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

/// A response head detached from any server/runtime representation.
#[derive(Debug, Clone)]
pub struct HttpResponseHead {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

/// Bytes still carrying their received content-coding representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireBody(Bytes);

impl WireBody {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    pub const fn bytes(&self) -> &Bytes {
        &self.0
    }
}

/// Bytes after an explicitly selected decoding step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody(Bytes);

impl DecodedBody {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    pub const fn bytes(&self) -> &Bytes {
        &self.0
    }
}

/// Typed header changes. Hooks never emit HTTP wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMutation {
    Set {
        name: HeaderName,
        value: HeaderValue,
    },
    Remove {
        name: HeaderName,
    },
}

/// Request/response-head mutation plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeadMutationPlan {
    pub headers: Vec<HeaderMutation>,
}

/// Bounded decoded-body mutation plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BodyMutationPlan {
    #[default]
    Keep,
    Replace(DecodedBody),
}

/// Typed TCP chunk transform.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChunkMutationPlan {
    #[default]
    Keep,
    Replace(Bytes),
    Drop,
}

pub trait HttpRequestHeadHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a HttpRequestHead) -> HookFuture<'a, HeadMutationPlan>;
}

pub trait HttpRequestBodyHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan>;
}

pub trait HttpResponseHeadHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a HttpResponseHead) -> HookFuture<'a, HeadMutationPlan>;
}

pub trait HttpResponseBodyHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan>;
}

pub trait TcpClientChunkHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan>;
}

pub trait TcpUpstreamChunkHook: Send + Sync {
    fn call<'a>(&'a self, input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan>;
}

/// In-process hook registry. Native dynamic libraries are deliberately unsupported.
#[derive(Default, Clone)]
pub struct HookRegistry {
    request_head: Vec<Arc<dyn HttpRequestHeadHook>>,
    request_body: Vec<Arc<dyn HttpRequestBodyHook>>,
    response_head: Vec<Arc<dyn HttpResponseHeadHook>>,
    response_body: Vec<Arc<dyn HttpResponseBodyHook>>,
    tcp_client: Vec<Arc<dyn TcpClientChunkHook>>,
    tcp_upstream: Vec<Arc<dyn TcpUpstreamChunkHook>>,
}

impl fmt::Debug for HookRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookRegistry")
            .field("request_head", &self.request_head.len())
            .field("request_body", &self.request_body.len())
            .field("response_head", &self.response_head.len())
            .field("response_body", &self.response_body.len())
            .field("tcp_client", &self.tcp_client.len())
            .field("tcp_upstream", &self.tcp_upstream.len())
            .finish()
    }
}

impl HookRegistry {
    pub fn register_request_head(&mut self, hook: Arc<dyn HttpRequestHeadHook>) {
        self.request_head.push(hook);
    }

    pub fn register_request_body(&mut self, hook: Arc<dyn HttpRequestBodyHook>) {
        self.request_body.push(hook);
    }

    pub fn register_response_head(&mut self, hook: Arc<dyn HttpResponseHeadHook>) {
        self.response_head.push(hook);
    }

    pub fn register_response_body(&mut self, hook: Arc<dyn HttpResponseBodyHook>) {
        self.response_body.push(hook);
    }

    pub fn register_tcp_client(&mut self, hook: Arc<dyn TcpClientChunkHook>) {
        self.tcp_client.push(hook);
    }

    pub fn register_tcp_upstream(&mut self, hook: Arc<dyn TcpUpstreamChunkHook>) {
        self.tcp_upstream.push(hook);
    }
}

/// Whether hook errors and timeouts preserve traffic or fail the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFailurePolicy {
    FailOpen,
    FailClosed,
}

/// Hook invocation failure at the policy boundary.
#[derive(Debug)]
pub enum HookRunError {
    Failed(HookError),
    TimedOut,
}

impl fmt::Display for HookRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(_) => formatter.write_str("registered hook failed"),
            Self::TimedOut => formatter.write_str("registered hook exceeded its execution budget"),
        }
    }
}

impl Error for HookRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failed(source) => Some(source),
            Self::TimedOut => None,
        }
    }
}

/// Executes one immutable registry according to runtime mode and budgets.
#[derive(Debug, Clone)]
pub struct HookRunner {
    mode: HookMode,
    registry: HookRegistry,
    timeout: Duration,
    failure_policy: HookFailurePolicy,
}

impl HookRunner {
    pub const fn new(
        mode: HookMode,
        registry: HookRegistry,
        timeout: Duration,
        failure_policy: HookFailurePolicy,
    ) -> Self {
        Self {
            mode,
            registry,
            timeout,
            failure_policy,
        }
    }

    pub const fn mode(&self) -> HookMode {
        self.mode
    }

    /// Reports whether request-body framing must allow a typed replacement.
    pub fn may_mutate_request_body(&self) -> bool {
        self.mode == HookMode::Interactive
            || (self.mode == HookMode::Automatic && !self.registry.request_body.is_empty())
    }

    /// Reports whether response-body framing must allow a typed replacement.
    pub fn may_mutate_response_body(&self) -> bool {
        self.mode == HookMode::Interactive
            || (self.mode == HookMode::Automatic && !self.registry.response_body.is_empty())
    }

    /// Runs registered request-head hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn request_head(
        &self,
        input: &HttpRequestHead,
    ) -> Result<HeadMutationPlan, HookRunError> {
        let mut combined = HeadMutationPlan::default();
        if self.mode == HookMode::Disabled {
            return Ok(combined);
        }
        for hook in &self.registry.request_head {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                combined.headers.extend(plan.headers);
            }
        }
        Ok(combined)
    }

    /// Runs registered request-body hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn request_body(&self, input: &WireBody) -> Result<BodyMutationPlan, HookRunError> {
        let mut mutation = BodyMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.request_body {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs registered response-head hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn response_head(
        &self,
        input: &HttpResponseHead,
    ) -> Result<HeadMutationPlan, HookRunError> {
        let mut combined = HeadMutationPlan::default();
        if self.mode == HookMode::Disabled {
            return Ok(combined);
        }
        for hook in &self.registry.response_head {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                combined.headers.extend(plan.headers);
            }
        }
        Ok(combined)
    }

    /// Runs registered response-body hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn response_body(&self, input: &WireBody) -> Result<BodyMutationPlan, HookRunError> {
        let mut mutation = BodyMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.response_body {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs client-to-upstream TCP hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn tcp_client_chunk(&self, input: &Bytes) -> Result<ChunkMutationPlan, HookRunError> {
        let mut mutation = ChunkMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.tcp_client {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs upstream-to-client TCP hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn tcp_upstream_chunk(
        &self,
        input: &Bytes,
    ) -> Result<ChunkMutationPlan, HookRunError> {
        let mut mutation = ChunkMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.tcp_upstream {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    async fn invoke<T>(&self, future: HookFuture<'_, T>) -> Result<Option<T>, HookRunError> {
        match tokio::time::timeout(self.timeout, future).await {
            Ok(Ok(value)) => Ok(Some(value)),
            Ok(Err(_)) | Err(_) if self.failure_policy == HookFailurePolicy::FailOpen => Ok(None),
            Ok(Err(error)) => Err(HookRunError::Failed(error)),
            Err(_) => Err(HookRunError::TimedOut),
        }
    }
}

/// Invalid or unsafe mutation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    ProtectedHeader { name: HeaderName },
    BodyTooLarge { actual: usize, maximum: usize },
    EncodedBodyReplacement,
}

impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedHeader { name } => {
                write!(
                    formatter,
                    "hook may not mutate proxy-controlled header {name}"
                )
            }
            Self::BodyTooLarge { actual, maximum } => write!(
                formatter,
                "hook replacement body contains {actual} bytes, exceeding the configured limit {maximum}"
            ),
            Self::EncodedBodyReplacement => formatter.write_str(
                "decoded body replacement cannot be applied after content encoding is committed",
            ),
        }
    }
}

impl Error for MutationError {}

/// Applies typed headers and reconstructs body framing after replacement.
///
/// # Errors
///
/// Returns [`MutationError`] when a plan attempts to mutate hop-by-hop framing.
pub fn apply_http_mutation(
    headers: &mut HeaderMap,
    body: &WireBody,
    head: &HeadMutationPlan,
    body_plan: &BodyMutationPlan,
    maximum_replacement_bytes: usize,
) -> Result<Bytes, MutationError> {
    apply_head_mutation(headers, head)?;
    let output = apply_body_mutation(body, body_plan, maximum_replacement_bytes)?;
    if matches!(body_plan, BodyMutationPlan::Replace(_)) {
        normalize_replaced_body_headers(headers);
    }
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    if let Ok(length) = HeaderValue::from_str(&output.len().to_string()) {
        headers.insert(header::CONTENT_LENGTH, length);
    }
    Ok(output)
}

/// Removes representation metadata that would make a decoded replacement look
/// like the original encoded body.
pub fn normalize_replaced_body_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_ENCODING);
    headers.remove(header::CONTENT_RANGE);
    headers.remove(header::ETAG);
    headers.remove("content-md5");
    headers.remove("digest");
}

/// Applies a typed body plan while enforcing the configured replacement bound.
/// An unchanged body is permitted even when an incoming streaming chunk is
/// larger than the replacement budget.
///
/// # Errors
///
/// Returns [`MutationError::BodyTooLarge`] when a replacement exceeds the
/// configured maximum.
pub fn apply_body_mutation(
    body: &WireBody,
    body_plan: &BodyMutationPlan,
    maximum_replacement_bytes: usize,
) -> Result<Bytes, MutationError> {
    match body_plan {
        BodyMutationPlan::Keep => Ok(body.bytes().clone()),
        BodyMutationPlan::Replace(replacement)
            if replacement.bytes().len() > maximum_replacement_bytes =>
        {
            Err(MutationError::BodyTooLarge {
                actual: replacement.bytes().len(),
                maximum: maximum_replacement_bytes,
            })
        }
        BodyMutationPlan::Replace(replacement) => Ok(replacement.bytes().clone()),
    }
}

/// Applies a typed request/response-head plan without altering body framing.
///
/// # Errors
///
/// Returns [`MutationError`] when a plan attempts to mutate hop-by-hop framing.
pub fn apply_head_mutation(
    headers: &mut HeaderMap,
    head: &HeadMutationPlan,
) -> Result<(), MutationError> {
    for mutation in &head.headers {
        match mutation {
            HeaderMutation::Set { name, value } => {
                validate_mutable_header(name)?;
                headers.insert(name, value.clone());
            }
            HeaderMutation::Remove { name } => {
                validate_mutable_header(name)?;
                headers.remove(name);
            }
        }
    }
    Ok(())
}

fn validate_mutable_header(name: &HeaderName) -> Result<(), MutationError> {
    if matches!(
        name.as_str(),
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "content-length"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return Err(MutationError::ProtectedHeader { name: name.clone() });
    }
    Ok(())
}

/// Context copied into a bounded interactive request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptContext {
    pub session_id: SessionId,
    pub transaction_id: Option<TransactionId>,
}

/// Hook stage paused for a bounded interactive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptStage {
    HttpRequestHead,
    HttpRequestBody,
    HttpResponseHead,
    HttpResponseBody,
    TcpClientChunk,
    TcpUpstreamChunk,
}

/// TUI/manual action returned through a oneshot response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveDecision {
    Continue,
    Reject,
    EditHeaders(HeadMutationPlan),
    ReplaceBody(DecodedBody),
    CancelModification,
}

/// One paused flow delivered through the bounded interactive channel.
pub struct InterceptRequest {
    pub context: InterceptContext,
    pub stage: InterceptStage,
    pub response: oneshot::Sender<InteractiveDecision>,
}

impl fmt::Debug for InterceptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterceptRequest")
            .field("context", &self.context)
            .field("stage", &self.stage)
            .finish_non_exhaustive()
    }
}

/// Explicit timeout behavior for interactive interception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptTimeoutPolicy {
    FailOpen,
    FailClosed,
}

/// Interactive request failure or bounded-flow saturation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptError {
    Saturated,
    ChannelClosed,
    TimedOut,
    ResponderDropped,
}

impl fmt::Display for InterceptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Saturated => formatter.write_str("maximum paused flows reached"),
            Self::ChannelClosed => formatter.write_str("interactive request channel is closed"),
            Self::TimedOut => formatter.write_str("interactive decision timed out"),
            Self::ResponderDropped => formatter.write_str("interactive responder was dropped"),
        }
    }
}

impl Error for InterceptError {}

/// Producer side of bounded interactive interception.
#[derive(Debug, Clone)]
pub struct InteractiveBroker {
    sender: mpsc::Sender<InterceptRequest>,
    paused: Arc<Semaphore>,
    timeout: Duration,
    timeout_policy: InterceptTimeoutPolicy,
}

impl InteractiveBroker {
    /// Creates independent bounded request and paused-flow limits.
    ///
    /// # Errors
    ///
    /// Returns [`InterceptError::Saturated`] when either limit is zero.
    pub fn channel(
        capacity: usize,
        maximum_paused_flows: usize,
        timeout: Duration,
        timeout_policy: InterceptTimeoutPolicy,
    ) -> Result<(Self, mpsc::Receiver<InterceptRequest>), InterceptError> {
        if capacity == 0 || maximum_paused_flows == 0 {
            return Err(InterceptError::Saturated);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok((
            Self {
                sender,
                paused: Arc::new(Semaphore::new(maximum_paused_flows)),
                timeout,
                timeout_policy,
            },
            receiver,
        ))
    }

    /// Pauses one flow without waiting for bounded capacity.
    ///
    /// # Errors
    ///
    /// Returns an explicit saturation, channel, timeout, or responder error.
    pub async fn intercept(
        &self,
        context: InterceptContext,
        stage: InterceptStage,
    ) -> Result<InteractiveDecision, InterceptError> {
        let _permit = Arc::clone(&self.paused)
            .try_acquire_owned()
            .map_err(|_| InterceptError::Saturated)?;
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(InterceptRequest {
                context,
                stage,
                response,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => InterceptError::Saturated,
                mpsc::error::TrySendError::Closed(_) => InterceptError::ChannelClosed,
            })?;
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(decision)) => Ok(decision),
            Ok(Err(_)) => Err(InterceptError::ResponderDropped),
            Err(_) if self.timeout_policy == InterceptTimeoutPolicy::FailOpen => {
                Ok(InteractiveDecision::Continue)
            }
            Err(_) => Err(InterceptError::TimedOut),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bytes::Bytes;
    use freja_domain::{HookMode, SessionId};
    use http::{HeaderMap, HeaderValue, header};

    use super::{
        BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HookError,
        HookFailurePolicy, HookFuture, HookRegistry, HookRunError, HookRunner, HttpRequestBodyHook,
        InteractiveBroker, InterceptContext, InterceptError, InterceptStage,
        InterceptTimeoutPolicy, MutationError, WireBody, apply_head_mutation, apply_http_mutation,
    };

    struct CountingHook(Arc<AtomicUsize>);

    impl HttpRequestBodyHook for CountingHook {
        fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(BodyMutationPlan::Keep) })
        }
    }

    struct PendingHook;

    impl HttpRequestBodyHook for PendingHook {
        fn call<'a>(&'a self, _input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn disabled_mode_does_not_invoke_registered_hook() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut registry = HookRegistry::default();
        registry.register_request_body(Arc::new(CountingHook(Arc::clone(&calls))));
        let runner = HookRunner::new(
            HookMode::Disabled,
            registry,
            Duration::from_millis(10),
            HookFailurePolicy::FailClosed,
        );

        let result = runner.request_body(&WireBody::new("body")).await.unwrap();

        assert_eq!(result, BodyMutationPlan::Keep);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn hook_timeout_obeys_fail_closed_policy() {
        let mut registry = HookRegistry::default();
        registry.register_request_body(Arc::new(PendingHook));
        let runner = HookRunner::new(
            HookMode::Automatic,
            registry,
            Duration::from_millis(1),
            HookFailurePolicy::FailClosed,
        );

        let result = runner.request_body(&WireBody::new("body")).await;

        assert!(matches!(result, Err(HookRunError::TimedOut)));
    }

    #[test]
    fn body_replacement_reconstructs_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::ETAG, HeaderValue::from_static("old-validator"));
        let output = apply_http_mutation(
            &mut headers,
            &WireBody::new("old"),
            &HeadMutationPlan::default(),
            &BodyMutationPlan::Replace(DecodedBody::new("longer")),
            64,
        )
        .unwrap();

        assert_eq!(output, Bytes::from_static(b"longer"));
        assert_eq!(headers[header::CONTENT_LENGTH], "6");
        assert!(!headers.contains_key(header::CONTENT_ENCODING));
        assert!(!headers.contains_key(header::ETAG));
    }

    #[test]
    fn oversized_body_replacement_is_rejected() {
        let mut headers = HeaderMap::new();
        let error = apply_http_mutation(
            &mut headers,
            &WireBody::new("old"),
            &HeadMutationPlan::default(),
            &BodyMutationPlan::Replace(DecodedBody::new("too-large")),
            4,
        )
        .unwrap_err();

        assert_eq!(
            error,
            MutationError::BodyTooLarge {
                actual: 9,
                maximum: 4,
            }
        );
    }

    #[test]
    fn head_hooks_cannot_override_body_framing() {
        let mut headers = HeaderMap::new();
        let name = header::CONTENT_LENGTH;
        let error = apply_head_mutation(
            &mut headers,
            &HeadMutationPlan {
                headers: vec![HeaderMutation::Set {
                    name: name.clone(),
                    value: HeaderValue::from_static("999"),
                }],
            },
        )
        .unwrap_err();

        assert_eq!(error, MutationError::ProtectedHeader { name });
    }

    #[tokio::test]
    async fn paused_flow_limit_and_timeout_are_explicit() {
        let (broker, mut receiver) = InteractiveBroker::channel(
            1,
            1,
            Duration::from_millis(10),
            InterceptTimeoutPolicy::FailClosed,
        )
        .unwrap();
        let context = InterceptContext {
            session_id: SessionId::new(),
            transaction_id: None,
        };
        let first_broker = broker.clone();
        let first = tokio::spawn(async move {
            first_broker
                .intercept(context, InterceptStage::TcpClientChunk)
                .await
        });
        let request = receiver.recv().await.unwrap();
        let second = broker
            .intercept(context, InterceptStage::TcpClientChunk)
            .await;
        assert_eq!(second, Err(InterceptError::Saturated));
        drop(request);
        let first = first.await.unwrap();
        assert!(matches!(
            first,
            Err(InterceptError::ResponderDropped | InterceptError::TimedOut)
        ));
    }

    #[test]
    fn hook_error_message_is_concrete() {
        assert_eq!(HookError::new("failed").to_string(), "failed");
    }
}
