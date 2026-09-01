use serde::{Deserialize, Serialize};

use crate::{PolicyGeneration, RuleId, UpstreamEndpoint};

/// Stage at which policy made a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyStage {
    /// The requested host and port before DNS resolution.
    RequestedDestination,
    /// One concrete IP address returned by DNS resolution.
    ResolvedDestination,
    /// A normalized HTTP request before upstream forwarding.
    HttpRequest,
    /// An upstream HTTP response before downstream commitment.
    HttpResponse,
    /// A bounded chunk observed while a body or TCP stream is in flight.
    Streaming,
}

/// One human-readable fact that contributed to a matching rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReason {
    /// Stable name of the criterion that matched.
    pub criterion: String,
    /// Human-readable, sanitized value observed by the evaluator.
    pub observed: String,
}

/// HTTP rejection variants that are legal before response commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpReject {
    /// Reject with HTTP status 403.
    Forbidden,
    /// Reject with HTTP status 451.
    UnavailableForLegalReasons,
    /// Request proxy credentials with HTTP status 407.
    ProxyAuthenticationRequired,
}

/// How a TCP flow is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpCloseMode {
    /// Attempt an orderly shutdown that permits buffered bytes to drain.
    Graceful,
    /// Abort the connection without an orderly shutdown.
    Reset,
}

/// A policy instruction to close a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpClose {
    /// Wire-level behavior to use when closing the connection.
    pub mode: TcpCloseMode,
}

/// A policy-selected replacement upstream for a TCP connection before relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpDetour {
    /// Replacement destination selected before relay begins.
    pub destination: UpstreamEndpoint,
}

/// Closed initial set of protocol-aware enforcement actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details", rename_all = "kebab-case")]
pub enum EnforcementAction {
    /// Continue processing the flow without a policy intervention.
    Allow,
    /// Emit an HTTP rejection before the response is committed.
    HttpReject(HttpReject),
    /// Close a TCP flow using the specified transport behavior.
    TcpClose(TcpClose),
    /// Connect a TCP flow to a policy-selected replacement upstream.
    TcpDetour(TcpDetour),
}

/// Stable action category embedded in decision traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementActionKind {
    /// Category corresponding to [`EnforcementAction::Allow`].
    Allow,
    /// Category corresponding to [`EnforcementAction::HttpReject`].
    HttpReject,
    /// Category corresponding to [`EnforcementAction::TcpClose`].
    TcpClose,
    /// Category corresponding to [`EnforcementAction::TcpDetour`].
    TcpDetour,
}

impl EnforcementAction {
    /// Returns the stable category for audit and UI use.
    pub const fn kind(&self) -> EnforcementActionKind {
        match self {
            Self::Allow => EnforcementActionKind::Allow,
            Self::HttpReject(_) => EnforcementActionKind::HttpReject,
            Self::TcpClose(_) => EnforcementActionKind::TcpClose,
            Self::TcpDetour(_) => EnforcementActionKind::TcpDetour,
        }
    }
}

/// Deterministic explanation of a policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Immutable policy snapshot used for this evaluation.
    pub policy_generation: PolicyGeneration,
    /// Flow lifecycle stage at which the decision was made.
    pub evaluated_stage: PolicyStage,
    /// First matching rule, or `None` when the default action was selected.
    pub matched_rule: Option<RuleId>,
    /// Sanitized facts that explain why the rule matched.
    pub match_reasons: Vec<MatchReason>,
    /// Stable category of the resulting protocol action.
    pub final_action: EnforcementActionKind,
}

/// Protocol action and its explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Protocol action proposed by policy.
    pub action: EnforcementAction,
    /// Deterministic explanation that must accompany the action into audit and UI paths.
    pub trace: DecisionTrace,
}
