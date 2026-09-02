#![forbid(unsafe_code)]

//! Immutable UI events and a best-effort bounded publisher.
//!
//! [`UiPublisher`] is cloneable across network tasks. Publishing never waits
//! for capacity and therefore cannot put backpressure on forwarding; dropped
//! snapshots are counted explicitly. Enable the `tui` feature for the
//! terminal-owning ratatui consumer.
//!
//! # Example
//!
//! ```
//! use freja_ui::{UiEvent, UiPublishOutcome, UiPublisher};
//!
//! # fn main() -> Result<(), freja_ui::UiChannelError> {
//! let (publisher, _receiver) = UiPublisher::channel(1)?;
//! let event = || UiEvent::OperationalLog { message: "ready".to_owned() };
//!
//! assert_eq!(publisher.try_publish(event()), UiPublishOutcome::Published);
//! assert_eq!(publisher.try_publish(event()), UiPublishOutcome::DroppedFull);
//! assert_eq!(publisher.dropped_events(), 1);
//! # Ok(())
//! # }
//! ```

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
    OperationalLog {
        /// Bounded, display-ready log text.
        message: String,
    },
    /// A listener admitted a new flow.
    FlowOpened {
        /// Connection correlation identity.
        session_id: SessionId,
        /// Peer address formatted for presentation.
        client: String,
        /// Requested or static target formatted for presentation.
        target: String,
    },
    /// Parsed HTTP request metadata became available.
    HttpObserved {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Parsed method.
        method: String,
        /// Original request target; terminal presentation treats it as sensitive.
        target: String,
        /// Parsed HTTP version used by the semantic view.
        version: String,
        /// Request headers copied before forwarding normalization.
        headers: Vec<(String, Vec<u8>)>,
    },
    /// Parsed HTTP response metadata became available.
    HttpResponseObserved {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Parsed HTTP status code.
        status: u16,
        /// Parsed HTTP version used by the semantic view.
        version: String,
        /// Response headers copied at the observation boundary.
        headers: Vec<(String, Vec<u8>)>,
    },
    /// Policy produced an explainable decision.
    DecisionMade {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Immutable policy explanation.
        trace: DecisionTrace,
    },
    /// Inspection produced a finding without directly enforcing it.
    FindingDetected {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Immutable detector output with hashed evidence by default.
        finding: Finding,
    },
    /// Explicit capture produced a bounded body snapshot.
    BodyPrefix {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Logical traffic direction.
        direction: Direction,
        /// Copied bytes that consumers must treat as sensitive.
        bytes: Vec<u8>,
        /// Offset of the first byte within this logical direction.
        offset: u64,
        /// Total bytes observed after this event.
        observed_bytes: u64,
        /// Whether later or current bytes exceeded the retention bound.
        truncated: bool,
    },
    /// A bounded exact HTTP/1 wire message captured before normalization.
    WireCaptured {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Request or response direction.
        direction: Direction,
        /// Exact retained bytes including HTTP/1 framing.
        bytes: Vec<u8>,
        /// Full observed message length.
        observed_bytes: u64,
        /// Whether bytes beyond the retention bound were omitted.
        truncated: bool,
    },
    /// Exact HTTP/1 wire capture failed without affecting forwarding.
    WireCaptureFailed {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Request or response direction.
        direction: Direction,
        /// Stable, secret-free capture diagnostic.
        reason: String,
    },
    /// Exact wire capture is not applicable to this semantic HTTP exchange.
    WireCaptureUnavailable {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Request or response direction without an ingress wire snapshot.
        direction: Direction,
        /// Stable explanation suitable for local presentation.
        reason: String,
    },
    /// A flow reached its terminal state.
    FlowClosed {
        /// Connection correlation identity.
        session_id: SessionId,
        /// Total bytes relayed from client to upstream.
        client_to_upstream_bytes: u64,
        /// Total bytes relayed from upstream to client.
        upstream_to_client_bytes: u64,
    },
}

/// Failure to create a bounded UI event channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiChannelError {
    /// Capacity zero would make every best-effort event undeliverable.
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
    /// The bounded channel accepted the event.
    Published,
    /// The event was dropped because the consumer was behind.
    DroppedFull,
    /// The event was dropped because the consumer had shut down.
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
