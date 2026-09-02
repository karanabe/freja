use freja_domain::{HookMode, TransactionId};
use freja_policy::hook::{
    BodyMutationPlan, HttpRequestHead, HttpRequestSnapshot, HttpResponseHead, InteractiveDecision,
    WireBody, apply_body_mutation, apply_head_mutation, apply_http_mutation,
};
use http::{Request, Response};
use hyper::body::Incoming;

use super::{HttpService, ProxyError, audit_context};

impl HttpService {
    pub(super) async fn pause_connect_request(
        &self,
        transaction_id: TransactionId,
        request: &mut Request<Incoming>,
    ) -> Result<(), ProxyError> {
        if self.services.hooks().mode() != HookMode::Interactive {
            return Ok(());
        }
        let context = audit_context(self.session_id, Some(transaction_id), &self.services);
        let snapshot = HttpRequestSnapshot {
            method: request.method().clone(),
            uri: request.uri().clone(),
            version: request.version(),
            headers: request.headers().clone(),
            body: WireBody::new(bytes::Bytes::new()),
            maximum_head_bytes: self.limits.header_bytes,
            maximum_body_bytes: 0,
        };
        match self
            .services
            .interactive_http_request(context, transaction_id, snapshot)
            .await?
        {
            Some(InteractiveDecision::EditHeaders(plan)) => {
                apply_head_mutation(request.headers_mut(), &plan).map_err(ProxyError::HookMutation)
            }
            Some(InteractiveDecision::ReplaceBody(replacement)) => apply_body_mutation(
                &WireBody::new(bytes::Bytes::new()),
                &BodyMutationPlan::Replace(replacement),
                0,
            )
            .map(|_| ())
            .map_err(ProxyError::HookMutation),
            Some(InteractiveDecision::ModifyRequest(plan)) => apply_http_mutation(
                request.headers_mut(),
                &WireBody::new(bytes::Bytes::new()),
                &plan.head,
                &plan.body,
                0,
            )
            .map(|_| ())
            .map_err(ProxyError::HookMutation),
            Some(InteractiveDecision::Reject) => Err(ProxyError::InteractiveRejected),
            Some(InteractiveDecision::Continue | InteractiveDecision::CancelModification)
            | None => Ok(()),
        }
    }

    pub(super) async fn apply_request_head_hooks(
        &self,
        transaction_id: TransactionId,
        request: &mut Request<Incoming>,
    ) -> Result<(), ProxyError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpRequestHead {
            method: request.method().clone(),
            uri: request.uri().clone(),
            headers: request.headers().clone(),
        };
        let result = self.services.hooks().request_head(&input).await;
        let context = audit_context(self.session_id, Some(transaction_id), &self.services);
        self.services
            .publish_hook_outcome(context, "http-request-head", result.is_ok())
            .await?;
        let plan = result.map_err(ProxyError::Hook)?;
        apply_head_mutation(request.headers_mut(), &plan).map_err(ProxyError::HookMutation)
    }

    pub(super) async fn apply_response_head_hooks(
        &self,
        transaction_id: TransactionId,
        response: &mut Response<Incoming>,
    ) -> Result<(), ProxyError> {
        if self.services.hooks().mode() == HookMode::Disabled {
            return Ok(());
        }
        let input = HttpResponseHead {
            status: response.status(),
            headers: response.headers().clone(),
        };
        let result = self.services.hooks().response_head(&input).await;
        let context = audit_context(self.session_id, Some(transaction_id), &self.services);
        self.services
            .publish_hook_outcome(context, "http-response-head", result.is_ok())
            .await?;
        let plan = result.map_err(ProxyError::Hook)?;
        apply_head_mutation(response.headers_mut(), &plan).map_err(ProxyError::HookMutation)
    }
}
