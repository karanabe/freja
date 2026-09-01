#![forbid(unsafe_code)]

//! Runtime- and framework-independent domain types shared by Freja's control
//! and data planes. Protocol-aware facts and actions remain detached from wire
//! parsers and networking runtimes.

pub mod decision;
pub mod endpoint;
pub mod finding;
pub mod flow;
pub mod ids;
pub mod listener;
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
