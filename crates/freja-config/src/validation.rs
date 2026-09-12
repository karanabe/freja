mod audit;
mod inspection;
mod limits;
mod listener;
mod safety;
mod tls;

use freja_domain::{
    HookMode, InspectionMode, ListenerSpec, PolicyGeneration, RuntimeProfile, UiMode,
};
use freja_policy::{AclRule, InspectionPattern, RuleAction};

pub use self::{
    audit::{AuditConfig, CheckpointSigningConfig},
    inspection::CapturePolicy,
    limits::Limits,
    safety::{ListenerExposure, SafetyConfig},
    tls::{TlsConfig, TlsInterception},
};

use crate::{RawConfig, RawInspection, RawPolicy, ValidationError};

/// Configuration whose external values and cross-field constraints are valid.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub(crate) runtime: RuntimeProfile,
    pub(crate) safety: SafetyConfig,
    pub(crate) limits: Limits,
    pub(crate) audit: AuditConfig,
    pub(crate) capture: CapturePolicy,
    pub(crate) inspection_mode: InspectionMode,
    pub(crate) inspection_patterns: Vec<InspectionPattern>,
    pub(crate) tls: TlsConfig,
    pub(crate) generation: PolicyGeneration,
    pub(crate) default_action: RuleAction,
    pub(crate) rules: Vec<AclRule>,
    pub(crate) listeners: Vec<ListenerSpec>,
}

impl TryFrom<RawConfig> for ValidatedConfig {
    type Error = ValidationError;

    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let RawConfig {
            runtime,
            safety,
            limits: raw_limits,
            audit: raw_audit,
            capture: raw_capture,
            inspection: raw_inspection,
            tls: raw_tls,
            policy: raw_policy,
            listeners: raw_listeners,
        } = raw;

        if runtime.hooks == HookMode::Interactive && runtime.ui != UiMode::Tui {
            return Err(ValidationError::InteractiveHooksRequireTui);
        }
        if raw_listeners.is_empty() {
            return Err(ValidationError::NoListeners);
        }

        let safety = SafetyConfig::from(safety);
        let limits = Limits::try_from(raw_limits)?;
        if runtime.hooks == HookMode::Interactive
            && limits.ui_content_bytes() < limits.body_prefix_bytes()
        {
            return Err(ValidationError::UiContentBelowBodyLimit {
                ui_content_bytes: limits.ui_content_bytes(),
                body_prefix_bytes: limits.body_prefix_bytes(),
            });
        }
        let capture = CapturePolicy::try_from((raw_capture, limits.body_prefix_bytes()))?;
        let RawInspection {
            mode: inspection_mode,
            patterns,
        } = raw_inspection;
        let inspection_patterns =
            inspection::validate_patterns(patterns, limits.body_prefix_bytes())?;
        let tls = tls::validate(raw_tls)?;
        let audit = AuditConfig::try_from(raw_audit)?;

        let RawPolicy {
            generation,
            default_action,
            rules,
        } = raw_policy;
        let generation =
            PolicyGeneration::new(generation).map_err(|_| ValidationError::ZeroPolicyGeneration)?;
        let listeners = listener::validate_all(raw_listeners, safety.permits_non_loopback_bind())?;

        Ok(Self {
            runtime,
            safety,
            limits,
            audit,
            capture,
            inspection_mode,
            inspection_patterns,
            tls,
            generation,
            default_action,
            rules,
            listeners,
        })
    }
}
