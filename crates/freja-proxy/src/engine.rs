/// Transport/runtime implementation selected by bootstrap code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    PingoraServerApp,
    TokioFallback,
}

/// Narrow boundary that keeps policy and protocol semantics independent of listeners.
pub trait ListenerEngine: Send + Sync {
    /// Identifies the runtime adapter for diagnostics and audit metadata.
    fn kind(&self) -> EngineKind;
}

/// Pure Tokio listener fallback behind Freja's protocol-engine boundary.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioEngine;

impl ListenerEngine for TokioEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::TokioFallback
    }
}
