use serde::{Deserialize, Serialize};

/// Whether Freja owns a terminal UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UiMode {
    /// Run without acquiring or rendering a terminal.
    #[default]
    Headless,
    /// Run the ratatui interface on its isolated terminal owner.
    Tui,
}

/// Whether policy denials are observed or executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementMode {
    /// Record decisions while allowing traffic to continue.
    #[default]
    Observe,
    /// Execute the protocol action selected by policy.
    Enforce,
}

/// How registered request, response, and stream hooks are invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookMode {
    /// Never invoke registered hooks; this is the secure default.
    #[default]
    Disabled,
    /// Invoke registered hooks without pausing for an operator.
    Automatic,
    /// Pause bounded flows for an operator decision subject to a timeout.
    Interactive,
}

/// CONNECT handling. Interception is always an explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsHandling {
    /// Relay encrypted bytes without terminating TLS.
    #[default]
    Tunnel,
    /// Terminate TLS only for explicitly allowed hosts using configured CA material.
    Intercept,
}

/// Independent runtime choices for presentation, enforcement, and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeProfile {
    /// Presentation mode; it does not alter policy enforcement.
    pub ui: UiMode,
    /// Whether policy actions are observed or executed.
    pub enforcement: EnforcementMode,
    /// Invocation mode for registered transformation hooks.
    pub hooks: HookMode,
}
