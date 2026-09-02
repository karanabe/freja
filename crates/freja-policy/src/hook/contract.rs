use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

/// Boxed async result returned by a registered hook without an async-trait dependency.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HookError>> + Send + 'a>>;

/// Hook-supplied failure with a stable, secret-free message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookError {
    message: String,
}

impl HookError {
    /// Creates a hook failure from a stable message that is safe to expose in diagnostics.
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
    /// HTTP method after request-line parsing.
    pub method: Method,
    /// Normalized request URI; it is not raw wire text.
    pub uri: Uri,
    /// Framing-validated request headers.
    pub headers: HeaderMap,
}

/// A response head detached from any server/runtime representation.
#[derive(Debug, Clone)]
pub struct HttpResponseHead {
    /// Upstream response status before downstream commitment.
    pub status: StatusCode,
    /// Framing-validated response headers.
    pub headers: HeaderMap,
}

/// Bytes still carrying their received content-coding representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireBody(Bytes);

impl WireBody {
    /// Marks received bytes as still carrying their wire content coding.
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the immutable wire representation.
    pub const fn bytes(&self) -> &Bytes {
        &self.0
    }
}

/// Bytes after an explicitly selected decoding step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody(Bytes);

impl DecodedBody {
    /// Marks bytes as decoded and eligible for typed body replacement.
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the immutable decoded representation.
    pub const fn bytes(&self) -> &Bytes {
        &self.0
    }
}

/// Typed header changes. Hooks never emit HTTP wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderMutation {
    /// Insert or replace one end-to-end header.
    Set {
        /// Header to set; proxy-controlled framing names are rejected when applied.
        name: HeaderName,
        /// Validated header value.
        value: HeaderValue,
    },
    /// Append one value without discarding existing values for the same name.
    Append {
        /// Header to append; proxy-controlled framing names are rejected when applied.
        name: HeaderName,
        /// Validated header value.
        value: HeaderValue,
    },
    /// Remove one end-to-end header.
    Remove {
        /// Header to remove; proxy-controlled framing names are rejected when applied.
        name: HeaderName,
    },
}

/// Request/response-head mutation plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeadMutationPlan {
    /// Ordered changes applied before the proxy reconstructs framing.
    pub headers: Vec<HeaderMutation>,
}

/// Combined typed mutation for one interactively paused HTTP request.
///
/// Keeping the head and body plans together lets an operator submit one
/// atomic edit while the HTTP engine remains responsible for validation and
/// framing reconstruction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpRequestMutationPlan {
    /// Ordered end-to-end header mutations.
    pub head: HeadMutationPlan,
    /// Bounded decoded-body mutation.
    pub body: BodyMutationPlan,
}

/// Bounded decoded-body mutation plan.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum BodyMutationPlan {
    #[default]
    /// Forward the received representation unchanged.
    Keep,
    /// Replace the body with bounded decoded bytes and rebuild representation headers.
    Replace(DecodedBody),
}

/// Typed TCP chunk transform.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChunkMutationPlan {
    #[default]
    /// Relay the input chunk unchanged.
    Keep,
    /// Relay replacement bytes subject to the runtime's output handling.
    Replace(Bytes),
    /// Suppress this chunk without closing the flow.
    Drop,
}

/// Asynchronous hook invoked for request metadata before upstream forwarding.
pub trait HttpRequestHeadHook: Send + Sync {
    /// Produces a typed request-head plan; implementations must honor the runner's time budget.
    fn call<'a>(&'a self, input: &'a HttpRequestHead) -> HookFuture<'a, HeadMutationPlan>;
}

/// Asynchronous hook invoked for a bounded request-body representation.
pub trait HttpRequestBodyHook: Send + Sync {
    /// Produces a typed body plan without directly changing HTTP framing.
    fn call<'a>(&'a self, input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan>;
}

/// Asynchronous hook invoked before an upstream response is committed downstream.
pub trait HttpResponseHeadHook: Send + Sync {
    /// Produces a typed response-head plan; implementations must be cancellation safe.
    fn call<'a>(&'a self, input: &'a HttpResponseHead) -> HookFuture<'a, HeadMutationPlan>;
}

/// Asynchronous hook invoked for a bounded response-body representation.
pub trait HttpResponseBodyHook: Send + Sync {
    /// Produces a typed body plan without directly changing HTTP framing.
    fn call<'a>(&'a self, input: &'a WireBody) -> HookFuture<'a, BodyMutationPlan>;
}

/// Asynchronous transform for a client-to-upstream TCP chunk.
pub trait TcpClientChunkHook: Send + Sync {
    /// Produces a typed chunk plan within the configured execution budget.
    fn call<'a>(&'a self, input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan>;
}

/// Asynchronous transform for an upstream-to-client TCP chunk.
pub trait TcpUpstreamChunkHook: Send + Sync {
    /// Produces a typed chunk plan within the configured execution budget.
    fn call<'a>(&'a self, input: &'a Bytes) -> HookFuture<'a, ChunkMutationPlan>;
}

/// In-process hook registry. Native dynamic libraries are deliberately unsupported.
#[derive(Default, Clone)]
pub struct HookRegistry {
    pub(super) request_head: Vec<Arc<dyn HttpRequestHeadHook>>,
    pub(super) request_body: Vec<Arc<dyn HttpRequestBodyHook>>,
    pub(super) response_head: Vec<Arc<dyn HttpResponseHeadHook>>,
    pub(super) response_body: Vec<Arc<dyn HttpResponseBodyHook>>,
    pub(super) tcp_client: Vec<Arc<dyn TcpClientChunkHook>>,
    pub(super) tcp_upstream: Vec<Arc<dyn TcpUpstreamChunkHook>>,
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
    /// Appends a request-head hook to declaration-order execution.
    pub fn register_request_head(&mut self, hook: Arc<dyn HttpRequestHeadHook>) {
        self.request_head.push(hook);
    }

    /// Appends a request-body hook to declaration-order execution.
    pub fn register_request_body(&mut self, hook: Arc<dyn HttpRequestBodyHook>) {
        self.request_body.push(hook);
    }

    /// Appends a response-head hook to declaration-order execution.
    pub fn register_response_head(&mut self, hook: Arc<dyn HttpResponseHeadHook>) {
        self.response_head.push(hook);
    }

    /// Appends a response-body hook to declaration-order execution.
    pub fn register_response_body(&mut self, hook: Arc<dyn HttpResponseBodyHook>) {
        self.response_body.push(hook);
    }

    /// Appends a client-to-upstream TCP hook to declaration-order execution.
    pub fn register_tcp_client(&mut self, hook: Arc<dyn TcpClientChunkHook>) {
        self.tcp_client.push(hook);
    }

    /// Appends an upstream-to-client TCP hook to declaration-order execution.
    pub fn register_tcp_upstream(&mut self, hook: Arc<dyn TcpUpstreamChunkHook>) {
        self.tcp_upstream.push(hook);
    }
}
