use freja_domain::{SessionId, TransactionId};

use super::HttpRequestSnapshot;
use crate::hook::InterceptContext;

/// One bounded HTTP/1.1 request submitted from a retained TUI repeat workspace.
///
/// The immutable method, absolute target, and version originate at the
/// interactive interception boundary. Only the bounded headers and body may
/// have been edited by the operator.
#[derive(Debug, Clone)]
pub struct RepeatRequest {
    /// Correlation and original source address of the intercepted request.
    pub source: InterceptContext,
    /// Complete bounded semantic request to validate and execute again.
    pub request: HttpRequestSnapshot,
}

/// Latest result returned to the TUI for one repeat workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatResult {
    /// Original transaction that owns the retained workspace.
    pub source_transaction_id: TransactionId,
    /// Fresh session identity assigned to this repeat attempt.
    pub session_id: SessionId,
    /// Fresh HTTP exchange identity assigned to this repeat attempt.
    pub transaction_id: TransactionId,
    /// Semantic response or a stable, secret-free failure category.
    pub outcome: RepeatOutcome,
}

/// Terminal outcome of one repeat attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepeatOutcome {
    /// A complete response was received and its body was retained up to the UI bound.
    Response(HttpResponseSnapshot),
    /// The attempt failed before a complete response was available.
    Failed(RepeatFailureCategory),
}

/// Bounded semantic response retained by a repeat workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseSnapshot {
    /// Upstream or locally generated status code.
    pub status: http::StatusCode,
    /// Parsed response version.
    pub version: http::Version,
    /// Validated and normalized response headers.
    pub headers: http::HeaderMap,
    /// Retained response-body prefix.
    pub body: Vec<u8>,
    /// Total response-body bytes observed after transformations.
    pub observed_body_bytes: u64,
    /// Whether the body exceeded the TUI retention bound.
    pub body_truncated: bool,
}

/// Stable failure categories safe to present without leaking request content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeatFailureCategory {
    /// The retained draft violated HTTP/1.1, target, framing, or size invariants.
    InvalidRequest,
    /// Current enforcement policy rejected the requested or resolved destination.
    PolicyDenied,
    /// Name resolution failed or timed out.
    Dns,
    /// No authorized upstream address could be connected.
    Connect,
    /// HTTPS repeat was unavailable or upstream TLS authentication failed.
    Tls,
    /// The upstream HTTP exchange failed or timed out.
    Upstream,
    /// Inspection or a typed hook rejected or failed the exchange.
    Inspection,
    /// Critical audit publication failed under fail-closed policy.
    Audit,
    /// Graceful shutdown cancelled the attempt.
    Shutdown,
    /// An internal lifecycle boundary could not complete.
    Internal,
}

impl std::fmt::Display for RepeatFailureCategory {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid request",
            Self::PolicyDenied => "policy denied",
            Self::Dns => "DNS failed",
            Self::Connect => "connection failed",
            Self::Tls => "TLS failed",
            Self::Upstream => "upstream HTTP failed",
            Self::Inspection => "inspection or hook failed",
            Self::Audit => "audit publication failed",
            Self::Shutdown => "shutdown",
            Self::Internal => "internal lifecycle failure",
        })
    }
}
