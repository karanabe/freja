use freja_audit::{AuditEnvelope, AuditEvent};
use freja_domain::Direction;
use freja_policy::hook::{
    ChunkMutationPlan, InteractiveDecision, InterceptContext, InterceptStage,
};

use crate::ProxyError;

use super::DataPlaneServices;

impl DataPlaneServices {
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
