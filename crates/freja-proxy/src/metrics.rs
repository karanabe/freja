use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use freja_audit::AuditEvent;

/// Lock-free process-local data-plane counters suitable for a control-plane
/// exporter without putting backpressure on forwarding tasks.
#[derive(Debug, Clone, Default)]
pub struct DataPlaneMetrics {
    inner: Arc<MetricCounters>,
}

#[derive(Debug, Default)]
struct MetricCounters {
    accepted_flows: AtomicU64,
    closed_flows: AtomicU64,
    policy_actions: AtomicU64,
    findings: AtomicU64,
    client_to_upstream_bytes: AtomicU64,
    upstream_to_client_bytes: AtomicU64,
    tls_interceptions: AtomicU64,
    tls_leaf_cache_hits: AtomicU64,
    tls_leaf_cache_misses: AtomicU64,
    manual_actions: AtomicU64,
}

/// Consistent-enough monotonic metric sample. Individual fields can advance
/// while a snapshot is read, as expected for lock-free operational metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub accepted_flows: u64,
    pub active_flows: u64,
    pub closed_flows: u64,
    pub policy_actions: u64,
    pub findings: u64,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub tls_interceptions: u64,
    pub tls_leaf_cache_hits: u64,
    pub tls_leaf_cache_misses: u64,
    pub manual_actions: u64,
    pub audit_rejected_events: u64,
    pub ui_dropped_events: u64,
}

impl DataPlaneMetrics {
    pub(crate) fn observe(&self, event: &AuditEvent) {
        match event {
            AuditEvent::ConnectionAccepted { .. } => increment(&self.inner.accepted_flows, 1),
            AuditEvent::FlowClosed {
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                ..
            } => {
                increment(&self.inner.closed_flows, 1);
                increment(
                    &self.inner.client_to_upstream_bytes,
                    *client_to_upstream_bytes,
                );
                increment(
                    &self.inner.upstream_to_client_bytes,
                    *upstream_to_client_bytes,
                );
            }
            AuditEvent::TunnelClosed {
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                ..
            } => {
                increment(
                    &self.inner.client_to_upstream_bytes,
                    *client_to_upstream_bytes,
                );
                increment(
                    &self.inner.upstream_to_client_bytes,
                    *upstream_to_client_bytes,
                );
            }
            AuditEvent::ActionExecuted { .. } => increment(&self.inner.policy_actions, 1),
            AuditEvent::FindingDetected { .. } => increment(&self.inner.findings, 1),
            AuditEvent::TlsCertificateGenerated { cache_hit, .. } => {
                if *cache_hit {
                    increment(&self.inner.tls_leaf_cache_hits, 1);
                } else {
                    increment(&self.inner.tls_leaf_cache_misses, 1);
                }
            }
            AuditEvent::TlsInterceptionEstablished { .. } => {
                increment(&self.inner.tls_interceptions, 1);
            }
            AuditEvent::ManualModification { .. } => increment(&self.inner.manual_actions, 1),
            AuditEvent::TargetResolved { .. }
            | AuditEvent::AclEvaluated { .. }
            | AuditEvent::HttpRequestObserved { .. }
            | AuditEvent::HttpResponseObserved { .. }
            | AuditEvent::ProxyAuthentication { .. }
            | AuditEvent::SignedCheckpoint { .. }
            | AuditEvent::InspectionEvaluated { .. }
            | AuditEvent::ReplayFactsObserved { .. }
            | AuditEvent::PayloadPrefixCaptured { .. }
            | AuditEvent::HookExecuted { .. } => {}
        }
    }

    pub(crate) fn snapshot_with_delivery(
        &self,
        audit_rejected_events: u64,
        ui_dropped_events: u64,
    ) -> MetricsSnapshot {
        let accepted_flows = load(&self.inner.accepted_flows);
        let closed_flows = load(&self.inner.closed_flows);
        MetricsSnapshot {
            accepted_flows,
            active_flows: accepted_flows.saturating_sub(closed_flows),
            closed_flows,
            policy_actions: load(&self.inner.policy_actions),
            findings: load(&self.inner.findings),
            client_to_upstream_bytes: load(&self.inner.client_to_upstream_bytes),
            upstream_to_client_bytes: load(&self.inner.upstream_to_client_bytes),
            tls_interceptions: load(&self.inner.tls_interceptions),
            tls_leaf_cache_hits: load(&self.inner.tls_leaf_cache_hits),
            tls_leaf_cache_misses: load(&self.inner.tls_leaf_cache_misses),
            manual_actions: load(&self.inner.manual_actions),
            audit_rejected_events,
            ui_dropped_events,
        }
    }
}

fn increment(counter: &AtomicU64, value: u64) {
    let _previous = counter.fetch_add(value, Ordering::Relaxed);
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}
