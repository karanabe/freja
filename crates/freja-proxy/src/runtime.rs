use std::sync::Arc;

use arc_swap::ArcSwap;
use freja_audit::AuditPublisher;
use freja_policy::hook::{HookRunner, InteractiveBroker};

use crate::{DataPlaneEventSink, DataPlaneMetrics, TlsInterceptor};

mod hooks;
mod publication;
mod snapshot;

pub(crate) use snapshot::DecisionSnapshot;
use snapshot::PolicySnapshot;

/// Immutable policy and publishers shared by independent connection tasks.
#[derive(Debug, Clone)]
pub struct DataPlaneServices {
    snapshot: Arc<ArcSwap<PolicySnapshot>>,
    audit: AuditPublisher,
    events: Option<Arc<dyn DataPlaneEventSink>>,
    hooks: Arc<HookRunner>,
    tls: Option<Arc<TlsInterceptor>>,
    interactive: Option<InteractiveBroker>,
    metrics: DataPlaneMetrics,
    capture_prefix_bytes: Option<usize>,
}
