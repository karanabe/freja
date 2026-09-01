use std::fmt;

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};

/// Immutable data-plane fact offered to best-effort observers.
///
/// These events describe proxy activity without choosing a presentation. They
/// are separate from critical security audit records and must never influence
/// forwarding decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPlaneEvent {
    /// A listener admitted a new flow.
    FlowOpened {
        /// Connection correlation identity.
        session_id: SessionId,
        /// Peer address formatted for presentation.
        client: String,
        /// Requested or static target formatted for presentation.
        target: String,
    },
    /// Normalized HTTP request metadata became available.
    HttpObserved {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Normalized HTTP method.
        method: String,
        /// Normalized request target with secrets removed upstream.
        target: String,
    },
    /// Policy produced an explainable decision.
    DecisionMade {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Immutable explanation safe for presentation.
        trace: DecisionTrace,
    },
    /// A detector produced a finding without directly enforcing it.
    FindingDetected {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Immutable detector output with hashed evidence by default.
        finding: Finding,
    },
    /// Explicitly enabled capture produced a bounded presentation snapshot.
    BodyPrefix {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange identity when applicable.
        transaction_id: Option<TransactionId>,
        /// Logical traffic direction.
        direction: Direction,
        /// Bounded copied bytes; consumers must treat them as sensitive.
        bytes: Vec<u8>,
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

/// Non-blocking observer boundary for immutable data-plane events.
///
/// Implementations must return immediately from [`Self::try_publish`]. Queue
/// saturation or a disconnected consumer must be counted and reported through
/// [`Self::dropped_events`], never propagated into network forwarding.
pub trait DataPlaneEventSink: Send + Sync + fmt::Debug {
    /// Offers one event without blocking; implementations may drop it and increment a metric.
    fn try_publish(&self, event: DataPlaneEvent);

    /// Returns the monotonic number of events dropped by this sink.
    fn dropped_events(&self) -> u64;
}
