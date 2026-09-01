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
