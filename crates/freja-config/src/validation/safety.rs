use freja_policy::{DestinationAccess, DestinationGuardSettings};

use crate::RawSafety;

/// Validated policy for listener exposure beyond loopback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerExposure {
    /// Only loopback listener addresses are accepted.
    LoopbackOnly,
    /// Authenticated HTTP and SOCKS proxy listeners may bind beyond loopback.
    AuthenticatedProxyAllowed,
}

/// Safety choices retained after raw configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyConfig {
    listener_exposure: ListenerExposure,
    destination_guards: DestinationGuardSettings,
}

impl SafetyConfig {
    /// Returns the validated listener exposure policy.
    pub const fn listener_exposure(self) -> ListenerExposure {
        self.listener_exposure
    }

    /// Returns post-resolution access for private destinations.
    pub const fn private_destinations(self) -> DestinationAccess {
        self.destination_guards.private
    }

    /// Returns post-resolution access for link-local destinations.
    pub const fn link_local_destinations(self) -> DestinationAccess {
        self.destination_guards.link_local
    }

    /// Returns post-resolution access for loopback destinations.
    pub const fn loopback_destinations(self) -> DestinationAccess {
        self.destination_guards.loopback
    }

    /// Returns post-resolution access for metadata-service destinations.
    pub const fn metadata_destinations(self) -> DestinationAccess {
        self.destination_guards.metadata
    }

    pub(super) const fn permits_non_loopback_bind(self) -> bool {
        matches!(
            self.listener_exposure,
            ListenerExposure::AuthenticatedProxyAllowed
        )
    }

    pub(crate) const fn destination_guard_settings(self) -> DestinationGuardSettings {
        self.destination_guards
    }
}

impl From<RawSafety> for SafetyConfig {
    fn from(raw: RawSafety) -> Self {
        let listener_exposure = if raw.allow_non_loopback {
            ListenerExposure::AuthenticatedProxyAllowed
        } else {
            ListenerExposure::LoopbackOnly
        };
        Self {
            listener_exposure,
            destination_guards: DestinationGuardSettings {
                private: raw.private_destinations,
                link_local: raw.link_local_destinations,
                loopback: raw.loopback_destinations,
                metadata: raw.metadata_destinations,
            },
        }
    }
}
