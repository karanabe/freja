use std::{error::Error, fmt, net::IpAddr, sync::Arc, time::Duration};

use freja_domain::{SessionId, TransactionId};
use tokio::sync::{Semaphore, mpsc, oneshot};

use super::{DecodedBody, HeadMutationPlan, HttpRequestMutationPlan, WireBody};

/// Immutable parsed request copied into an interactive TUI decision.
#[derive(Debug, Clone)]
pub struct HttpRequestSnapshot {
    /// Parsed request method.
    pub method: http::Method,
    /// Canonical absolute request URI for an HTTP/1.1 request, or the parsed
    /// boundary URI for request forms that cannot be repeated.
    pub uri: http::Uri,
    /// Parsed HTTP version at the interception boundary.
    pub version: http::Version,
    /// Framing-validated request headers.
    pub headers: http::HeaderMap,
    /// Fully collected bounded request body.
    pub body: WireBody,
    /// Maximum edited request-head bytes accepted by the data plane.
    pub maximum_head_bytes: usize,
    /// Maximum edited request-body bytes accepted by the data plane.
    pub maximum_body_bytes: usize,
}

/// Context copied into a bounded interactive request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptContext {
    /// Flow paused for the operator decision.
    pub session_id: SessionId,
    /// Paused HTTP exchange.
    pub transaction_id: TransactionId,
    /// Original client address used when a local repeat attempt re-evaluates policy.
    pub source_ip: IpAddr,
}

/// TUI/manual action returned through a oneshot response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveDecision {
    /// Resume without mutation.
    Continue,
    /// Reject or close the flow while the protocol still permits it.
    Reject,
    /// Apply typed header changes and resume.
    EditHeaders(HeadMutationPlan),
    /// Replace a bounded body with decoded bytes and resume.
    ReplaceBody(DecodedBody),
    /// Atomically apply typed header and body changes and resume.
    ModifyRequest(HttpRequestMutationPlan),
    /// Discard a pending modification and resume unchanged.
    CancelModification,
}

/// One paused flow delivered through the bounded interactive channel.
pub struct InterceptRequest {
    /// Correlation identifiers copied from the paused flow.
    pub context: InterceptContext,
    /// Complete bounded HTTP request available for interactive editing.
    pub request: HttpRequestSnapshot,
    /// Single-use response channel; dropping it reports `ResponderDropped`.
    pub response: oneshot::Sender<InteractiveDecision>,
}

impl fmt::Debug for InterceptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterceptRequest")
            .field("context", &self.context)
            .field("method", &self.request.method)
            .field("uri", &self.request.uri)
            .finish_non_exhaustive()
    }
}

/// Explicit timeout behavior for interactive interception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptTimeoutPolicy {
    /// Resume unchanged when the operator misses the deadline.
    FailOpen,
    /// Return an error so enforcement can reject the flow.
    FailClosed,
}

/// Interactive request failure or bounded-flow saturation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptError {
    /// The request channel or paused-flow semaphore had no capacity.
    Saturated,
    /// The interactive consumer has shut down.
    ChannelClosed,
    /// No response arrived before a fail-closed deadline.
    TimedOut,
    /// The consumer dropped the oneshot responder without deciding.
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

    /// Pauses one complete bounded HTTP request for a single operator decision.
    ///
    /// # Errors
    ///
    /// Returns an explicit saturation, channel, timeout, or responder error.
    pub async fn intercept_http_request(
        &self,
        context: InterceptContext,
        request: HttpRequestSnapshot,
    ) -> Result<InteractiveDecision, InterceptError> {
        let _permit = Arc::clone(&self.paused)
            .try_acquire_owned()
            .map_err(|_| InterceptError::Saturated)?;
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(InterceptRequest {
                context,
                request,
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
