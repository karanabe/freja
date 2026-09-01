use std::{error::Error, fmt, sync::Arc, time::Duration};

use freja_domain::{SessionId, TransactionId};
use tokio::sync::{Semaphore, mpsc, oneshot};

use super::{DecodedBody, HeadMutationPlan};

/// Context copied into a bounded interactive request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptContext {
    /// Flow paused for the operator decision.
    pub session_id: SessionId,
    /// HTTP exchange, or `None` for connection-level/TCP interception.
    pub transaction_id: Option<TransactionId>,
}

/// Hook stage paused for a bounded interactive decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptStage {
    /// Request metadata before upstream forwarding.
    HttpRequestHead,
    /// Bounded request body before or during forwarding.
    HttpRequestBody,
    /// Response metadata before downstream commitment.
    HttpResponseHead,
    /// Bounded response body before or during forwarding.
    HttpResponseBody,
    /// Client-to-upstream TCP chunk.
    TcpClientChunk,
    /// Upstream-to-client TCP chunk.
    TcpUpstreamChunk,
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
    /// Discard a pending modification and resume unchanged.
    CancelModification,
}

/// One paused flow delivered through the bounded interactive channel.
pub struct InterceptRequest {
    /// Correlation identifiers copied from the paused flow.
    pub context: InterceptContext,
    /// Lifecycle point awaiting a decision.
    pub stage: InterceptStage,
    /// Single-use response channel; dropping it reports `ResponderDropped`.
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
