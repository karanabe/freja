use freja_audit::{
    AuditEnvelope, AuditEvent, AuditHookStage, HookOutcome, ManualModificationAction,
};
use freja_domain::Direction;
use freja_policy::hook::{
    ChunkMutationPlan, HttpRequestSnapshot, InteractiveDecision, InterceptContext,
};

use crate::ProxyError;

use super::DataPlaneServices;

impl DataPlaneServices {
    pub(crate) async fn interactive_http_request(
        &self,
        context: freja_audit::AuditContext,
        source_ip: std::net::IpAddr,
        transaction_id: freja_domain::TransactionId,
        request: HttpRequestSnapshot,
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
            .intercept_http_request(
                InterceptContext {
                    session_id: context.session_id(),
                    transaction_id,
                    source_ip,
                },
                request,
            )
            .await;
        let action = match &result {
            Ok(InteractiveDecision::Continue) => ManualModificationAction::Continue,
            Ok(InteractiveDecision::Reject) => ManualModificationAction::Reject,
            Ok(InteractiveDecision::EditHeaders(_)) => ManualModificationAction::EditHeaders,
            Ok(InteractiveDecision::ReplaceBody(_)) => ManualModificationAction::ReplaceBody,
            Ok(InteractiveDecision::ModifyRequest(_)) => ManualModificationAction::ModifyRequest,
            Ok(InteractiveDecision::CancelModification) => {
                ManualModificationAction::CancelModification
            }
            Err(_) => ManualModificationAction::Failed,
        };
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::ManualModification { action },
        })
        .await?;
        result.map(Some).map_err(ProxyError::Interactive)
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
        let (stage, result) = match direction {
            Direction::ClientToUpstream => (
                AuditHookStage::TcpClientChunk,
                self.hooks.tcp_client_chunk(&bytes).await,
            ),
            Direction::UpstreamToClient => (
                AuditHookStage::TcpUpstreamChunk,
                self.hooks.tcp_upstream_chunk(&bytes).await,
            ),
            Direction::HttpRequestBody | Direction::HttpResponseBody => {
                return Ok(ChunkMutationPlan::Keep);
            }
        };
        let outcome = if result.is_ok() {
            HookOutcome::Completed
        } else {
            HookOutcome::Failed
        };
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::HookExecuted { stage, outcome },
        })
        .await?;
        result.map_err(ProxyError::Hook)
    }

    pub(crate) async fn publish_hook_outcome(
        &self,
        context: freja_audit::AuditContext,
        stage: AuditHookStage,
        succeeded: bool,
    ) -> Result<(), ProxyError> {
        self.publish(AuditEnvelope {
            context,
            event: AuditEvent::HookExecuted {
                stage,
                outcome: if succeeded {
                    HookOutcome::Completed
                } else {
                    HookOutcome::Failed
                },
            },
        })
        .await
    }
}
