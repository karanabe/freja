use freja_audit::{AuditEnvelope, AuditEvent};
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
                    session_id: context.session_id,
                    transaction_id,
                },
                request,
            )
            .await;
        let action = match &result {
            Ok(InteractiveDecision::Continue) => "continue",
            Ok(InteractiveDecision::Reject) => "reject",
            Ok(InteractiveDecision::EditHeaders(_)) => "edit-headers",
            Ok(InteractiveDecision::ReplaceBody(_)) => "replace-body",
            Ok(InteractiveDecision::ModifyRequest(_)) => "modify-request",
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
        let (stage, result) = match direction {
            Direction::ClientToUpstream => (
                "tcp-client-chunk",
                self.hooks.tcp_client_chunk(&bytes).await,
            ),
            Direction::UpstreamToClient => (
                "tcp-upstream-chunk",
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
        result.map_err(ProxyError::Hook)
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
