use std::path::Path;

use freja_domain::{InspectionMode, ListenerSpec, RuntimeProfile};
use freja_policy::{AclPolicy, DestinationGuard, InspectionProgram};

use crate::{
    AuditConfig, CapturePolicy, ConfigError, Limits, RawConfig, RawSafety, TlsConfig,
    ValidatedConfig,
};

/// Fully compiled immutable configuration consumed by runtime tasks.
#[derive(Debug, Clone)]
pub struct CompiledConfig {
    runtime: RuntimeProfile,
    safety: RawSafety,
    limits: Limits,
    audit: AuditConfig,
    capture: CapturePolicy,
    inspection_mode: InspectionMode,
    inspection: InspectionProgram,
    tls: TlsConfig,
    listeners: Vec<ListenerSpec>,
    policy: AclPolicy,
    destination_guard: DestinationGuard,
}

impl CompiledConfig {
    /// Loads, validates, and compiles a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for file I/O, TOML decoding, validation, policy,
    /// or inspection compilation failures.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        RawConfig::read(path)?.validate()?.compile()
    }

    /// Returns the selected UI, enforcement, and hook modes.
    pub const fn runtime(&self) -> RuntimeProfile {
        self.runtime
    }

    /// Returns the validated destination and listener safety settings.
    pub const fn safety(&self) -> RawSafety {
        self.safety
    }

    /// Returns the validated resource and timeout limits.
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Returns the validated audit sink configuration.
    pub const fn audit(&self) -> &AuditConfig {
        &self.audit
    }

    /// Returns the bounded payload capture policy.
    pub const fn capture(&self) -> CapturePolicy {
        self.capture
    }

    /// Returns the selected inspection execution mode.
    pub const fn inspection_mode(&self) -> InspectionMode {
        self.inspection_mode
    }

    /// Returns the compiled fixed-pattern inspection program.
    pub const fn inspection(&self) -> &InspectionProgram {
        &self.inspection
    }

    /// Returns the validated tunnel or interception configuration.
    pub const fn tls(&self) -> &TlsConfig {
        &self.tls
    }

    /// Returns every validated listener specification in declaration order.
    pub fn listeners(&self) -> &[ListenerSpec] {
        &self.listeners
    }

    /// Returns the compiled declaration-ordered ACL policy.
    pub const fn policy(&self) -> &AclPolicy {
        &self.policy
    }

    /// Returns the compiled post-resolution destination guard.
    pub const fn destination_guard(&self) -> &DestinationGuard {
        &self.destination_guard
    }
}

impl ValidatedConfig {
    /// Compiles deterministic policy matchers and freezes the runtime snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Policy`] or [`ConfigError::Inspection`] when a
    /// validated policy representation cannot be compiled.
    pub fn compile(self) -> Result<CompiledConfig, ConfigError> {
        let policy = AclPolicy::new(self.generation, self.rules, self.default_action)
            .map_err(ConfigError::Policy)?;
        let destination_guard =
            DestinationGuard::new(self.destination_guard_settings).map_err(ConfigError::Policy)?;
        let inspection = InspectionProgram::new(self.generation, self.inspection_patterns)
            .map_err(ConfigError::Inspection)?;

        Ok(CompiledConfig {
            runtime: self.runtime,
            safety: self.safety,
            limits: self.limits,
            audit: self.audit,
            capture: self.capture,
            inspection_mode: self.inspection_mode,
            inspection,
            tls: self.tls,
            listeners: self.listeners,
            policy,
            destination_guard,
        })
    }
}
