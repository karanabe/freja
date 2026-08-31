#![forbid(unsafe_code)]

//! Immutable UI events and a best-effort bounded publisher.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

#[cfg(feature = "tui")]
pub mod tui;

/// Immutable snapshot sent from network tasks to presentation code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum UiEvent {
    /// One formatted operational log line routed through the bounded TUI channel.
    OperationalLog { message: String },
    FlowOpened {
        session_id: SessionId,
        client: String,
        target: String,
    },
    HttpObserved {
        session_id: SessionId,
        transaction_id: TransactionId,
        method: String,
        target: String,
    },
    DecisionMade {
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        trace: DecisionTrace,
    },
    FindingDetected {
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        finding: Finding,
    },
    BodyPrefix {
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        direction: Direction,
        bytes: Vec<u8>,
    },
    FlowClosed {
        session_id: SessionId,
        client_to_upstream_bytes: u64,
        upstream_to_client_bytes: u64,
    },
}

/// Failure to create a bounded UI event channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiChannelError {
    ZeroCapacity,
}

impl fmt::Display for UiChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroCapacity => formatter.write_str("UI channel capacity must be non-zero"),
        }
    }
}

impl Error for UiChannelError {}

/// Result of a non-blocking UI publish attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiPublishOutcome {
    Published,
    DroppedFull,
    DroppedClosed,
}

/// Best-effort sender. Saturation never blocks network forwarding.
#[derive(Debug, Clone)]
pub struct UiPublisher {
    sender: mpsc::Sender<UiEvent>,
    dropped: Arc<AtomicU64>,
}

/// Read-only UI delivery counters without retaining a sender channel.
#[derive(Debug, Clone)]
pub struct UiMetrics {
    dropped: Arc<AtomicU64>,
}

impl UiMetrics {
    /// Total snapshots dropped due to saturation or a closed consumer.
    pub fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl UiPublisher {
    /// Creates a bounded UI channel and its single consumer.
    ///
    /// # Errors
    ///
    /// Returns [`UiChannelError::ZeroCapacity`] when `capacity` is zero.
    pub fn channel(capacity: usize) -> Result<(Self, mpsc::Receiver<UiEvent>), UiChannelError> {
        if capacity == 0 {
            return Err(UiChannelError::ZeroCapacity);
        }
        let (sender, receiver) = mpsc::channel(capacity);
        Ok((
            Self {
                sender,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        ))
    }

    /// Attempts to publish without awaiting channel capacity.
    pub fn try_publish(&self, event: UiEvent) -> UiPublishOutcome {
        match self.sender.try_send(event) {
            Ok(()) => UiPublishOutcome::Published,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                UiPublishOutcome::DroppedFull
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                UiPublishOutcome::DroppedClosed
            }
        }
    }

    /// Total event snapshots dropped because the consumer was unavailable or slow.
    pub fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns metrics that do not keep the event channel open.
    pub fn metrics(&self) -> UiMetrics {
        UiMetrics {
            dropped: Arc::clone(&self.dropped),
        }
    }
}

#[cfg(test)]
mod tests {
    use freja_domain::SessionId;

    use super::{UiEvent, UiPublishOutcome, UiPublisher};

    #[test]
    fn saturation_is_non_blocking_and_counted() {
        let (publisher, _receiver) = UiPublisher::channel(1).unwrap();
        let event = || UiEvent::FlowClosed {
            session_id: SessionId::new(),
            client_to_upstream_bytes: 0,
            upstream_to_client_bytes: 0,
        };

        assert_eq!(publisher.try_publish(event()), UiPublishOutcome::Published);
        assert_eq!(
            publisher.try_publish(event()),
            UiPublishOutcome::DroppedFull
        );
        assert_eq!(publisher.dropped_events(), 1);
    }
}
