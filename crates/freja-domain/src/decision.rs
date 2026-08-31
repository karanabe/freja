use serde::{Deserialize, Serialize};

use crate::{PolicyGeneration, RuleId, UpstreamEndpoint};

/// Stage at which policy made a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyStage {
    RequestedDestination,
    ResolvedDestination,
    HttpRequest,
    HttpResponse,
    Streaming,
}

/// One human-readable fact that contributed to a matching rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReason {
    pub criterion: String,
    pub observed: String,
}

/// HTTP rejection variants that are legal before response commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpReject {
    Forbidden,
    UnavailableForLegalReasons,
    ProxyAuthenticationRequired,
}

/// How a TCP flow is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpCloseMode {
    Graceful,
    Reset,
}

/// A policy instruction to close a TCP flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpClose {
    pub mode: TcpCloseMode,
}

/// A policy-selected replacement upstream for a TCP connection before relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpDetour {
    pub destination: UpstreamEndpoint,
}

/// Closed initial set of protocol-aware enforcement actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "details", rename_all = "kebab-case")]
pub enum EnforcementAction {
    Allow,
    HttpReject(HttpReject),
    TcpClose(TcpClose),
    TcpDetour(TcpDetour),
}

/// Stable action category embedded in decision traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementActionKind {
    Allow,
    HttpReject,
    TcpClose,
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
    pub policy_generation: PolicyGeneration,
    pub evaluated_stage: PolicyStage,
    pub matched_rule: Option<RuleId>,
    pub match_reasons: Vec<MatchReason>,
    pub final_action: EnforcementActionKind,
}

/// Protocol action and its explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub action: EnforcementAction,
    pub trace: DecisionTrace,
}
