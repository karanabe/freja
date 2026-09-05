use std::sync::Arc;

use arc_swap::ArcSwap;
use freja_audit::AuditPublisher;
use freja_domain::{Decision, EnforcementAction, EnforcementMode, InspectionMode};
use freja_policy::{
    AclPolicy, DestinationGuard, InspectionProgram,
    hook::{HookFailurePolicy, HookRegistry, HookRunner, InteractiveBroker},
};

use crate::{
    CaptureSettings, DataPlaneEventSink, DataPlaneMetrics, TlsInterceptor, UiCaptureSettings,
};

use super::DataPlaneServices;

#[derive(Debug)]
pub(super) struct PolicySnapshot {
    policy: Arc<AclPolicy>,
    destination_guard: Arc<DestinationGuard>,
    enforcement: EnforcementMode,
    inspection_mode: InspectionMode,
    inspection: Arc<InspectionProgram>,
}

/// One atomically loaded, internally consistent set of reloadable decision
/// inputs. Holding this value pins all stages it is used for to one generation.
#[derive(Debug, Clone)]
pub(crate) struct DecisionSnapshot {
    inner: Arc<PolicySnapshot>,
}

impl DecisionSnapshot {
    pub(crate) fn policy(&self) -> &AclPolicy {
        &self.inner.policy
    }

    pub(crate) fn destination_guard(&self) -> &DestinationGuard {
        &self.inner.destination_guard
    }

    pub(crate) fn inspection(&self) -> &InspectionProgram {
        &self.inner.inspection
    }

    pub(crate) fn inspection_mode(&self) -> InspectionMode {
        self.inner.inspection_mode
    }

    pub(crate) fn enforcement(&self) -> EnforcementMode {
        self.inner.enforcement
    }

    pub(crate) fn permits(&self, decision: &Decision) -> bool {
        self.inner.enforcement == EnforcementMode::Observe
            || matches!(decision.action, EnforcementAction::Allow)
    }
}

impl DataPlaneServices {
    /// Creates data-plane services from one immutable compiled snapshot.
    pub fn new(
        policy: AclPolicy,
        destination_guard: DestinationGuard,
        enforcement: EnforcementMode,
        audit: AuditPublisher,
    ) -> Self {
        let inspection = InspectionProgram::empty(policy.generation());
        let hooks = HookRunner::new(
            freja_domain::HookMode::Disabled,
            HookRegistry::default(),
            std::time::Duration::from_secs(1),
            HookFailurePolicy::FailClosed,
        );
        let snapshot = PolicySnapshot {
            policy: Arc::new(policy),
            destination_guard: Arc::new(destination_guard),
            enforcement,
            inspection_mode: InspectionMode::Streaming,
            inspection: Arc::new(inspection),
        };
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
            audit,
            events: None,
            hooks: Arc::new(hooks),
            tls: None,
            interactive: None,
            metrics: DataPlaneMetrics::default(),
            capture_prefix_bytes: None,
            ui_capture: None,
        }
    }

    /// Installs one immutable inspection program and body-inspection mode.
    #[must_use]
    pub fn with_inspection(mut self, inspection: InspectionProgram, mode: InspectionMode) -> Self {
        let current = self.snapshot.load_full();
        self.snapshot = Arc::new(ArcSwap::from_pointee(PolicySnapshot {
            policy: Arc::clone(&current.policy),
            destination_guard: Arc::clone(&current.destination_guard),
            enforcement: current.enforcement,
            inspection_mode: mode,
            inspection: Arc::new(inspection),
        }));
        self
    }

    /// Atomically replaces all reloadable decision inputs. Existing per-flow
    /// scanners keep their original program while new decisions and flows use
    /// the newly published generation.
    pub fn reload(
        &self,
        policy: AclPolicy,
        destination_guard: DestinationGuard,
        enforcement: EnforcementMode,
        inspection: InspectionProgram,
        inspection_mode: InspectionMode,
    ) {
        self.snapshot.store(Arc::new(PolicySnapshot {
            policy: Arc::new(policy),
            destination_guard: Arc::new(destination_guard),
            enforcement,
            inspection_mode,
            inspection: Arc::new(inspection),
        }));
    }

    /// Installs a separate best-effort observer for immutable data-plane facts.
    #[must_use]
    pub fn with_event_sink<S>(mut self, sink: S) -> Self
    where
        S: DataPlaneEventSink + 'static,
    {
        self.events = Some(Arc::new(sink));
        self
    }

    /// Installs an immutable in-process typed-hook runner.
    #[must_use]
    pub fn with_hooks(mut self, hooks: HookRunner) -> Self {
        self.hooks = Arc::new(hooks);
        self
    }

    /// Installs an opt-in TLS interception engine. Its own allowlist remains
    /// authoritative for deciding whether an individual CONNECT is decrypted.
    #[must_use]
    pub fn with_tls_interceptor(mut self, interceptor: TlsInterceptor) -> Self {
        self.tls = Some(Arc::new(interceptor));
        self
    }

    /// Installs the producer side of bounded interactive interception.
    #[must_use]
    pub fn with_interactive_broker(mut self, broker: InteractiveBroker) -> Self {
        self.interactive = Some(broker);
        self
    }

    /// Enables explicitly configured bounded raw-prefix capture for audit and
    /// offline replay. Metadata-only remains the default.
    #[must_use]
    pub fn with_capture(mut self, capture: CaptureSettings) -> Self {
        self.capture_prefix_bytes = capture.maximum_prefix_bytes();
        self
    }

    /// Enables bounded sensitive-content snapshots for an attached live UI.
    #[must_use]
    pub const fn with_ui_capture(mut self, capture: UiCaptureSettings) -> Self {
        self.ui_capture = Some(capture);
        self
    }

    pub(crate) const fn capture_prefix_bytes(&self) -> Option<usize> {
        self.capture_prefix_bytes
    }

    pub(crate) const fn ui_capture_settings(&self) -> Option<UiCaptureSettings> {
        self.ui_capture
    }

    pub(crate) fn publishes_events(&self) -> bool {
        self.events.is_some()
    }

    pub(crate) fn decision_snapshot(&self) -> DecisionSnapshot {
        DecisionSnapshot {
            inner: self.snapshot.load_full(),
        }
    }

    pub(crate) fn policy(&self) -> Arc<AclPolicy> {
        Arc::clone(&self.snapshot.load().policy)
    }

    pub(crate) fn inspection_mode(&self) -> InspectionMode {
        self.snapshot.load().inspection_mode
    }

    pub(crate) fn hooks(&self) -> &HookRunner {
        &self.hooks
    }

    pub(crate) fn tls_interceptor(&self) -> Option<Arc<TlsInterceptor>> {
        self.tls.as_ref().map(Arc::clone)
    }
}
