use freja_audit::{AuditEnvelope, AuditEvent, AuditFailurePolicy, PublishError};
use freja_domain::{
    Decision, Direction, EnforcementMode, EvaluationTarget, Finding, Protocol, ReplayFacts,
    ResolvedTargetFacts, SessionId, TransactionId,
};
use freja_policy::evidence::RuleDefinition;
use tracing::warn;

use crate::{DataPlaneEvent, MetricsSnapshot, ProxyError};

use super::DataPlaneServices;

impl DataPlaneServices {
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
            self.events.as_ref().map_or(0, |sink| sink.dropped_events()),
        )
    }

    pub(crate) async fn publish_decision(
        &self,
        mut context: freja_audit::AuditContext,
        decision: Decision,
        definition: (RuleDefinition<'_>, EnforcementMode),
        target: EvaluationTarget,
    ) -> Result<(), ProxyError> {
        context.policy_generation = decision.trace.policy_generation;
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::AclEvaluated {
                decision: decision.clone(),
            },
        })
        .await?;
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::DecisionMade {
                session_id: context.session_id,
                transaction_id: context.transaction_id,
                trace: decision.trace,
                evidence: Some(definition.0.snapshot(definition.1)),
                target: Some(target),
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
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::FindingDetected {
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
        definition: (RuleDefinition<'_>, EnforcementMode),
        target: Option<&ResolvedTargetFacts>,
    ) -> Result<(), ProxyError> {
        context.policy_generation = decision.trace.policy_generation;
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::InspectionEvaluated {
                decision: decision.clone(),
            },
        })
        .await?;
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::DecisionMade {
                session_id: context.session_id,
                transaction_id: context.transaction_id,
                trace: decision.trace,
                evidence: Some(definition.0.snapshot(definition.1)),
                target: target.cloned().map(EvaluationTarget::Resolved),
            });
        }
        Ok(())
    }

    pub(crate) fn publish_http_event(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        method: String,
        target: String,
        version: String,
        headers: Vec<(String, Vec<u8>)>,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::HttpObserved {
                session_id,
                transaction_id,
                method,
                target,
                version,
                headers,
            });
        }
    }

    pub(crate) fn publish_http_response_event(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        status: u16,
        version: String,
        headers: Vec<(String, Vec<u8>)>,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::HttpResponseObserved {
                session_id,
                transaction_id,
                status,
                version,
                headers,
            });
        }
    }

    pub(crate) fn publish_flow_opened(
        &self,
        session_id: SessionId,
        client: String,
        target: String,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::FlowOpened {
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
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::FlowClosed {
                session_id,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn publish_body_prefix(
        &self,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        direction: Direction,
        bytes: &[u8],
        offset: u64,
        observed_bytes: u64,
        truncated: bool,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::BodyPrefix {
                session_id,
                transaction_id,
                direction,
                bytes: bytes.to_vec(),
                offset,
                observed_bytes,
                truncated,
            });
        }
    }

    pub(crate) fn publish_wire_capture(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        direction: Direction,
        bytes: Vec<u8>,
        observed_bytes: u64,
        truncated: bool,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::WireCaptured {
                session_id,
                transaction_id,
                direction,
                bytes,
                observed_bytes,
                truncated,
            });
        }
    }

    pub(crate) fn publish_wire_capture_failure(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        direction: Direction,
        reason: String,
    ) {
        warn!(
            session_id = %session_id,
            transaction_id = %transaction_id,
            direction = ?direction,
            reason,
            "best-effort HTTP/1 wire capture failed"
        );
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::WireCaptureFailed {
                session_id,
                transaction_id,
                direction,
                reason,
            });
        }
    }

    pub(crate) fn publish_wire_capture_unavailable(
        &self,
        session_id: SessionId,
        transaction_id: TransactionId,
        direction: Direction,
        reason: String,
    ) {
        if let Some(events) = &self.events {
            events.try_publish(DataPlaneEvent::WireCaptureUnavailable {
                session_id,
                transaction_id,
                direction,
                reason,
            });
        }
    }
}

impl From<PublishError> for ProxyError {
    fn from(error: PublishError) -> Self {
        Self::Audit(error)
    }
}
