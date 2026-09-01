#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Runtime- and framework-independent domain types shared by Freja's control
//! and data planes. Protocol-aware facts and actions remain detached from wire
//! parsers and networking runtimes.

/// Protocol-aware policy decisions and their explainable traces.
pub mod decision;
/// Validated listener and upstream endpoint value types.
pub mod endpoint;
/// Runtime-independent inspection findings and evidence metadata.
pub mod finding;
/// Facts captured at successive stages of a network flow.
pub mod flow;
/// Stable identifiers used to correlate flows, transactions, and policy data.
pub mod ids;
/// Validated listener specifications consumed by data-plane adapters.
pub mod listener;
/// Independent runtime mode selections.
pub mod mode;

pub use decision::{
    Decision, DecisionTrace, EnforcementAction, EnforcementActionKind, HttpReject, MatchReason,
    PolicyStage, TcpClose, TcpCloseMode, TcpDetour,
};
pub use endpoint::{EndpointError, HostName, ListenEndpoint, Port, TargetHost, UpstreamEndpoint};
pub use finding::{Confidence, Direction, EvidenceHash, Finding, InspectionMode, Severity};
pub use flow::{
    HttpRequestFacts, HttpResponseFacts, Protocol, ReplayFacts, RequestedTargetFacts,
    ResolvedTargetFacts, SanitizedHeaders,
};
pub use ids::{
    AuditSequence, DetectorId, IdError, PolicyGeneration, RuleId, SessionId, TransactionId,
};
pub use listener::{
    HttpForwardListener, ListenerError, ListenerSpec, ProxyAuthentication, ProxyCredentialHash,
    Socks5Listener, TcpStaticListener,
};
pub use mode::{EnforcementMode, HookMode, RuntimeProfile, TlsHandling, UiMode};
