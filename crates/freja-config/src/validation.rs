mod audit;
mod inspection;
mod limits;
mod listener;
mod tls;

use freja_domain::{
    HookMode, InspectionMode, ListenerSpec, PolicyGeneration, RuntimeProfile, UiMode,
};
use freja_policy::{AclRule, DestinationGuardSettings, InspectionPattern, RuleAction};

pub use self::{audit::AuditConfig, inspection::CapturePolicy, limits::Limits, tls::TlsConfig};

use crate::{RawConfig, RawInspection, RawPolicy, RawSafety, ValidationError};

/// Configuration whose external values and cross-field constraints are valid.
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    pub(crate) runtime: RuntimeProfile,
    pub(crate) safety: RawSafety,
    pub(crate) limits: Limits,
    pub(crate) audit: AuditConfig,
    pub(crate) capture: CapturePolicy,
    pub(crate) inspection_mode: InspectionMode,
    pub(crate) inspection_patterns: Vec<InspectionPattern>,
    pub(crate) tls: TlsConfig,
    pub(crate) generation: PolicyGeneration,
    pub(crate) destination_guard_settings: DestinationGuardSettings,
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

        let limits = Limits::try_from(raw_limits)?;
        let capture = CapturePolicy::try_from((raw_capture, limits.body_prefix_bytes))?;
        let RawInspection {
            mode: inspection_mode,
            patterns,
        } = raw_inspection;
        let inspection_patterns =
            inspection::validate_patterns(patterns, limits.body_prefix_bytes)?;
        let tls = tls::validate(raw_tls)?;
        let audit = AuditConfig::try_from(raw_audit)?;

        let RawPolicy {
            generation,
            default_action,
            rules,
        } = raw_policy;
        let generation =
            PolicyGeneration::new(generation).map_err(|_| ValidationError::ZeroPolicyGeneration)?;
        let destination_guard_settings = DestinationGuardSettings {
            private: safety.private_destinations,
            link_local: safety.link_local_destinations,
            loopback: safety.loopback_destinations,
            metadata: safety.metadata_destinations,
        };
        let listeners = listener::validate_all(raw_listeners, safety.allow_non_loopback)?;

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
            destination_guard_settings,
            default_action,
            rules,
            listeners,
        })
    }
}
