use std::sync::Arc;

use arc_swap::ArcSwap;
use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, AuditPublisher, PublishError};
use freja_config::CapturePolicy;
use freja_domain::{
    Decision, Direction, EnforcementAction, EnforcementMode, Finding, InspectionMode, Protocol,
    ReplayFacts, SessionId, TransactionId,
};
use freja_policy::{
    AclPolicy, DestinationGuard, InspectionProgram,
    hook::{ChunkMutationPlan, HookFailurePolicy, HookRegistry, HookRunner},
    hook::{InteractiveBroker, InteractiveDecision, InterceptContext, InterceptStage},
};
use freja_ui::{UiEvent, UiPublisher};
use tracing::warn;

use crate::{DataPlaneMetrics, MetricsSnapshot, ProxyError, TlsInterceptor};

/// Immutable policy and publishers shared by independent connection tasks.
#[derive(Debug, Clone)]
pub struct DataPlaneServices {
    snapshot: Arc<ArcSwap<PolicySnapshot>>,
    audit: AuditPublisher,
    ui: Option<UiPublisher>,
    hooks: Arc<HookRunner>,
    tls: Option<Arc<TlsInterceptor>>,
    interactive: Option<InteractiveBroker>,
    metrics: DataPlaneMetrics,
    capture_prefix_bytes: Option<usize>,
}

#[derive(Debug)]
struct PolicySnapshot {
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
            ui: None,
            hooks: Arc::new(hooks),
            tls: None,
            interactive: None,
            metrics: DataPlaneMetrics::default(),
            capture_prefix_bytes: None,
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

    /// Installs a separate best-effort publisher for immutable UI snapshots.
    #[must_use]
    pub fn with_ui(mut self, ui: UiPublisher) -> Self {
        self.ui = Some(ui);
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
    pub fn with_capture(mut self, capture: CapturePolicy) -> Self {
        self.capture_prefix_bytes = match capture {
            CapturePolicy::MetadataOnly => None,
            CapturePolicy::Prefix { max_bytes } => Some(max_bytes),
        };
        self
    }

    pub(crate) const fn capture_prefix_bytes(&self) -> Option<usize> {
        self.capture_prefix_bytes
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

    pub(crate) async fn interactive_decision(
        &self,
        context: freja_audit::AuditContext,
        stage: InterceptStage,
    ) -> Result<Option<InteractiveDecision>, ProxyError> {
        if self.hooks.mode() != freja_domain::HookMode::Interactive {
            return Ok(None);
        }
        let broker = self
            .interactive
            .as_ref()
            .ok_or(freja_policy::hook::InterceptError::ChannelClosed)
            .map_err(ProxyError::Interactive)?;
        let result = broker
            .intercept(
                InterceptContext {
                    session_id: context.session_id,
                    transaction_id: context.transaction_id,
                },
                stage,
            )
            .await;
        let action = match &result {
            Ok(InteractiveDecision::Continue) => "continue",
            Ok(InteractiveDecision::Reject) => "reject",
            Ok(InteractiveDecision::EditHeaders(_)) => "edit-headers",
            Ok(InteractiveDecision::ReplaceBody(_)) => "replace-body",
            Ok(InteractiveDecision::CancelModification) => "cancel-modification",
            Err(_) => "failed",
        };
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::ManualModification {
                action: action.to_owned(),
            },
        })
        .await?;
        result.map(Some).map_err(ProxyError::Interactive)
    }

    pub(crate) async fn publish(&self, envelope: AuditEnvelope) -> Result<(), ProxyError> {
        self.metrics.observe(&envelope.event);
        match self.audit.publish(envelope).await {
            Ok(()) => Ok(()),
            Err(error) if self.audit.failure_policy() == AuditFailurePolicy::FailOpen => {
                warn!(error = %error, "audit event rejected under fail-open policy");
                Ok(())
            }
            Err(error) => Err(ProxyError::Audit(error)),
        }
    }

    /// Samples lock-free data-plane and publisher-delivery counters.
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot_with_delivery(
            self.audit.rejected_events(),
            self.ui.as_ref().map_or(0, UiPublisher::dropped_events),
        )
    }

    pub(crate) async fn publish_decision(
        &self,
        mut context: freja_audit::AuditContext,
        decision: Decision,
    ) -> Result<(), ProxyError> {
        context.policy_generation = decision.trace.policy_generation;
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::AclEvaluated {
                decision: decision.clone(),
            },
        })
        .await?;
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::DecisionMade {
                session_id: context.session_id,
                transaction_id: context.transaction_id,
                trace: decision.trace,
            });
        }
        Ok(())
    }

    pub(crate) async fn publish_finding(
        &self,
        context: freja_audit::AuditContext,
        finding: Finding,
    ) -> Result<(), ProxyError> {
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::FindingDetected {
                finding: finding.clone(),
            },
        })
        .await?;
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::FindingDetected {
                session_id: context.session_id,
                transaction_id: context.transaction_id,
                finding,
            });
        }
        Ok(())
    }

    pub(crate) async fn publish_replay_facts(
        &self,
        context: freja_audit::AuditContext,
        facts: ReplayFacts,
    ) -> Result<(), ProxyError> {
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::ReplayFactsObserved { facts },
        })
        .await
    }

    pub(crate) async fn publish_capture(
        &self,
        context: freja_audit::AuditContext,
        direction: Direction,
        protocol: Protocol,
        bytes: &[u8],
    ) -> Result<(), ProxyError> {
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::PayloadPrefixCaptured {
                direction,
                protocol,
                bytes_hex: hex::encode(bytes),
            },
        })
        .await
    }

    pub(crate) async fn publish_inspection_decision(
        &self,
        mut context: freja_audit::AuditContext,
        decision: Decision,
    ) -> Result<(), ProxyError> {
        context.policy_generation = decision.trace.policy_generation;
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::InspectionEvaluated {
                decision: decision.clone(),
            },
        })
        .await?;
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::DecisionMade {
                session_id: context.session_id,
                transaction_id: context.transaction_id,
                trace: decision.trace,
            });
        }
        Ok(())
    }

    pub(crate) fn publish_http_ui(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        method: String,
        target: String,
    ) {
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::HttpObserved {
                session_id,
                transaction_id,
                method,
                target,
            });
        }
    }

    pub(crate) fn publish_flow_opened(
        &self,
        session_id: SessionId,
        client: String,
        target: String,
    ) {
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::FlowOpened {
                session_id,
                client,
                target,
            });
        }
    }

    pub(crate) fn publish_flow_closed(
        &self,
        session_id: SessionId,
        client_to_upstream_bytes: u64,
        upstream_to_client_bytes: u64,
    ) {
        if let Some(ui) = &self.ui {
            ui.try_publish(UiEvent::FlowClosed {
                session_id,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
            });
        }
    }

    pub(crate) fn publish_body_prefix(
        &self,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        direction: Direction,
        bytes: &[u8],
    ) {
        if let Some(ui) = &self.ui {
            let maximum = bytes.len().min(1_024);
            ui.try_publish(UiEvent::BodyPrefix {
                session_id,
                transaction_id,
                direction,
                bytes: bytes[..maximum].to_vec(),
            });
        }
    }

    pub(crate) async fn run_tcp_hook(
        &self,
        context: freja_audit::AuditContext,
        direction: Direction,
        bytes: bytes::Bytes,
    ) -> Result<ChunkMutationPlan, ProxyError> {
        if self.hooks.mode() == freja_domain::HookMode::Disabled {
            return Ok(ChunkMutationPlan::Keep);
        }
        let (stage, intercept_stage, result) = match direction {
            Direction::ClientToUpstream => (
                "tcp-client-chunk",
                InterceptStage::TcpClientChunk,
                self.hooks.tcp_client_chunk(&bytes).await,
            ),
            Direction::UpstreamToClient => (
                "tcp-upstream-chunk",
                InterceptStage::TcpUpstreamChunk,
                self.hooks.tcp_upstream_chunk(&bytes).await,
            ),
            Direction::HttpRequestBody | Direction::HttpResponseBody => {
                return Ok(ChunkMutationPlan::Keep);
            }
        };
        let outcome = if result.is_ok() {
            "completed"
        } else {
            "failed"
        };
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::HookExecuted {
                stage: stage.to_owned(),
                outcome: outcome.to_owned(),
            },
        })
        .await?;
        let automatic = result.map_err(ProxyError::Hook)?;
        match self.interactive_decision(context, intercept_stage).await? {
            Some(InteractiveDecision::Reject) => Err(ProxyError::InteractiveRejected),
            Some(
                InteractiveDecision::Continue
                | InteractiveDecision::CancelModification
                | InteractiveDecision::EditHeaders(_)
                | InteractiveDecision::ReplaceBody(_),
            )
            | None => Ok(automatic),
        }
    }

    pub(crate) async fn publish_hook_outcome(
        &self,
        context: freja_audit::AuditContext,
        stage: &'static str,
        succeeded: bool,
    ) -> Result<(), ProxyError> {
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::HookExecuted {
                stage: stage.to_owned(),
                outcome: if succeeded { "completed" } else { "failed" }.to_owned(),
            },
        })
        .await
    }
}

impl From<PublishError> for ProxyError {
    fn from(error: PublishError) -> Self {
        Self::Audit(error)
    }
}
