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
    /// Parsed HTTP request metadata became available.
    HttpObserved {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Parsed HTTP method.
        method: String,
        /// Original request target; presentation consumers must treat it as sensitive.
        target: String,
        /// Parsed HTTP version used by the semantic view.
        version: String,
        /// Original request headers copied before forwarding normalization.
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
        /// Offset of the first byte within this logical direction.
        offset: u64,
        /// Total bytes observed in this direction after this event.
        observed_bytes: u64,
        /// Whether bytes were omitted because the TUI retention bound was reached.
        truncated: bool,
    },
    /// A bounded exact HTTP/1 wire message was captured at an ingress boundary.
    WireCaptured {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Request or response direction represented by the bytes.
        direction: Direction,
        /// Exact retained bytes, including HTTP/1 framing.
        bytes: Vec<u8>,
        /// Full message length observed before retention truncation.
        observed_bytes: u64,
        /// Whether the exact message exceeded the retention bound.
        truncated: bool,
    },
    /// Exact wire capture failed independently of HTTP forwarding.
    WireCaptureFailed {
        /// Connection correlation identity.
        session_id: SessionId,
        /// HTTP exchange correlation identity.
        transaction_id: TransactionId,
        /// Request or response direction that could not be captured.
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
