use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::mpsc;

use crate::{AuditContext, AuditEvent, AuditFailurePolicy};

/// Owned event sent through the bounded audit publisher.
#[derive(Debug, Clone)]
pub struct AuditEnvelope {
    pub context: AuditContext,
    pub event: AuditEvent,
}

/// An explicit audit delivery failure; critical records are never silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    ChannelClosed,
    CapacityExhausted,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelClosed => formatter.write_str("audit channel is closed"),
            Self::CapacityExhausted => formatter.write_str("audit channel capacity is exhausted"),
        }
    }
}

impl Error for PublishError {}

/// Sender side of a bounded audit channel with explicit fail-open/fail-closed behavior.
#[derive(Debug, Clone)]
pub struct AuditPublisher {
    sender: mpsc::Sender<AuditEnvelope>,
    failure_policy: AuditFailurePolicy,
    rejected_events: Arc<AtomicU64>,
}

/// Failure to create an audit channel with a valid finite capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditChannelError {
    ZeroCapacity,
}

impl fmt::Display for AuditChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("audit channel capacity must be non-zero"),
        }
    }
}

impl Error for AuditChannelError {}

impl AuditPublisher {
    /// Creates a separate bounded publisher and its single-consumer receiver.
    ///
    /// # Errors
    ///
    /// Returns [`AuditChannelError::ZeroCapacity`] when `capacity` is zero.
    pub fn channel(
        capacity: usize,
        failure_policy: AuditFailurePolicy,
    ) -> Result<(Self, mpsc::Receiver<AuditEnvelope>), AuditChannelError> {
        if capacity == 0 {
            return Err(AuditChannelError::ZeroCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok((
            Self {
                sender,
                failure_policy,
                rejected_events: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        ))
    }

    /// Publishes an event. Fail-closed waits for capacity; fail-open returns an explicit error.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] when the consumer is closed, or when fail-open
    /// delivery finds the bounded channel at capacity.
    pub async fn publish(&self, envelope: AuditEnvelope) -> Result<(), PublishError> {
        match self.failure_policy {
            AuditFailurePolicy::FailClosed => self
                .sender
                .send(envelope)
                .await
                .map_err(|_| PublishError::ChannelClosed),
            AuditFailurePolicy::FailOpen => self.sender.try_send(envelope).map_err(|error| {
                self.rejected_events.fetch_add(1, Ordering::Relaxed);
                match error {
                    mpsc::error::TrySendError::Full(_) => PublishError::CapacityExhausted,
                    mpsc::error::TrySendError::Closed(_) => PublishError::ChannelClosed,
                }
            }),
        }
    }

    /// Number of fail-open events rejected due to channel failure or saturation.
    pub fn rejected_events(&self) -> u64 {
        self.rejected_events.load(Ordering::Relaxed)
    }

    /// Returns the delivery policy bootstrap selected for this publisher.
    pub const fn failure_policy(&self) -> AuditFailurePolicy {
        self.failure_policy
    }
}
