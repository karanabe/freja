use std::{error::Error, fmt, time::Duration};

use bytes::Bytes;
use freja_domain::HookMode;

use super::{
    BodyMutationPlan, ChunkMutationPlan, HeadMutationPlan, HookError, HookFuture, HookRegistry,
    HttpRequestHead, HttpResponseHead, WireBody,
};

/// Whether hook errors and timeouts preserve traffic or fail the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFailurePolicy {
    FailOpen,
    FailClosed,
}

/// Hook invocation failure at the policy boundary.
#[derive(Debug)]
pub enum HookRunError {
    Failed(HookError),
    TimedOut,
}

impl fmt::Display for HookRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(_) => formatter.write_str("registered hook failed"),
            Self::TimedOut => formatter.write_str("registered hook exceeded its execution budget"),
        }
    }
}

impl Error for HookRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Failed(source) => Some(source),
            Self::TimedOut => None,
        }
    }
}

/// Executes one immutable registry according to runtime mode and budgets.
#[derive(Debug, Clone)]
pub struct HookRunner {
    mode: HookMode,
    registry: HookRegistry,
    timeout: Duration,
    failure_policy: HookFailurePolicy,
}

impl HookRunner {
    pub const fn new(
        mode: HookMode,
        registry: HookRegistry,
        timeout: Duration,
        failure_policy: HookFailurePolicy,
    ) -> Self {
        Self {
            mode,
            registry,
            timeout,
            failure_policy,
        }
    }

    pub const fn mode(&self) -> HookMode {
        self.mode
    }

    /// Reports whether request-body framing must allow a typed replacement.
    pub fn may_mutate_request_body(&self) -> bool {
        self.mode == HookMode::Interactive
            || (self.mode == HookMode::Automatic && !self.registry.request_body.is_empty())
    }

    /// Reports whether response-body framing must allow a typed replacement.
    pub fn may_mutate_response_body(&self) -> bool {
        self.mode == HookMode::Interactive
            || (self.mode == HookMode::Automatic && !self.registry.response_body.is_empty())
    }

    /// Runs registered request-head hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn request_head(
        &self,
        input: &HttpRequestHead,
    ) -> Result<HeadMutationPlan, HookRunError> {
        let mut combined = HeadMutationPlan::default();
        if self.mode == HookMode::Disabled {
            return Ok(combined);
        }
        for hook in &self.registry.request_head {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                combined.headers.extend(plan.headers);
            }
        }
        Ok(combined)
    }

    /// Runs registered request-body hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn request_body(&self, input: &WireBody) -> Result<BodyMutationPlan, HookRunError> {
        let mut mutation = BodyMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.request_body {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs registered response-head hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn response_head(
        &self,
        input: &HttpResponseHead,
    ) -> Result<HeadMutationPlan, HookRunError> {
        let mut combined = HeadMutationPlan::default();
        if self.mode == HookMode::Disabled {
            return Ok(combined);
        }
        for hook in &self.registry.response_head {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                combined.headers.extend(plan.headers);
            }
        }
        Ok(combined)
    }

    /// Runs registered response-body hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn response_body(&self, input: &WireBody) -> Result<BodyMutationPlan, HookRunError> {
        let mut mutation = BodyMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.response_body {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs client-to-upstream TCP hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn tcp_client_chunk(&self, input: &Bytes) -> Result<ChunkMutationPlan, HookRunError> {
        let mut mutation = ChunkMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.tcp_client {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    /// Runs upstream-to-client TCP hooks.
    ///
    /// # Errors
    ///
    /// Returns [`HookRunError`] under fail-closed timeout or failure policy.
    pub async fn tcp_upstream_chunk(
        &self,
        input: &Bytes,
    ) -> Result<ChunkMutationPlan, HookRunError> {
        let mut mutation = ChunkMutationPlan::Keep;
        if self.mode == HookMode::Disabled {
            return Ok(mutation);
        }
        for hook in &self.registry.tcp_upstream {
            if let Some(plan) = self.invoke(hook.call(input)).await? {
                mutation = plan;
            }
        }
        Ok(mutation)
    }

    async fn invoke<T>(&self, future: HookFuture<'_, T>) -> Result<Option<T>, HookRunError> {
        match tokio::time::timeout(self.timeout, future).await {
            Ok(Ok(value)) => Ok(Some(value)),
            Ok(Err(_)) | Err(_) if self.failure_policy == HookFailurePolicy::FailOpen => Ok(None),
            Ok(Err(error)) => Err(HookRunError::Failed(error)),
            Err(_) => Err(HookRunError::TimedOut),
        }
    }
}
