use std::fmt;

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};

/// Immutable data-plane fact offered to best-effort observers.
///
/// These events describe proxy activity without choosing a presentation. They
/// are separate from critical security audit records and must never influence
/// forwarding decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPlaneEvent {
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

/// Non-blocking observer boundary for immutable data-plane events.
///
/// Implementations must return immediately from [`Self::try_publish`]. Queue
/// saturation or a disconnected consumer must be counted and reported through
/// [`Self::dropped_events`], never propagated into network forwarding.
pub trait DataPlaneEventSink: Send + Sync + fmt::Debug {
    fn try_publish(&self, event: DataPlaneEvent);

    fn dropped_events(&self) -> u64;
}
