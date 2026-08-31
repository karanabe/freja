use serde::{Deserialize, Serialize};

/// Whether Freja owns a terminal UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UiMode {
    #[default]
    Headless,
    Tui,
}

/// Whether policy denials are observed or executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementMode {
    #[default]
    Observe,
    Enforce,
}

/// How registered request, response, and stream hooks are invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookMode {
    #[default]
    Disabled,
    Automatic,
    Interactive,
}

/// CONNECT handling. Interception is always an explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsHandling {
    #[default]
    Tunnel,
    Intercept,
}

/// Independent runtime choices for presentation, enforcement, and hooks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeProfile {
    pub ui: UiMode,
    pub enforcement: EnforcementMode,
    pub hooks: HookMode,
}
