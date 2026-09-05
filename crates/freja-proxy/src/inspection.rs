use freja_domain::{
    Direction, InspectionMode, Protocol, ReplayFacts, ResolvedTargetFacts, SessionId, TransactionId,
};
use freja_policy::StreamScanner;
use freja_policy::hook::{
    BodyMutationPlan, ChunkMutationPlan, MutationError, WireBody, apply_body_mutation,
};

use crate::{
    DataPlaneServices, ProxyError,
    destination::{audit_context, record_action},
    runtime::DecisionSnapshot,
};

/// Per-flow detector state with an independent bounded suffix for each direction.
pub(crate) struct FlowInspector {
    services: DataPlaneServices,
    decision: DecisionSnapshot,
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    protocol: Protocol,
    target: Option<ResolvedTargetFacts>,
    mode: InspectionMode,
    client_to_upstream: StreamScanner,
    upstream_to_client: StreamScanner,
    http_request_body: StreamScanner,
    http_response_body: StreamScanner,
    captured_bytes: [usize; 4],
    ui_observed_bytes: [u64; 4],
    ui_retained_bytes: [usize; 4],
    ui_truncation_reported: [bool; 4],
    maximum_inspected_bytes: usize,
    inspected_bytes: [usize; 4],
}

pub(crate) struct BodyTransform {
    pub bytes: bytes::Bytes,
    pub replaced: bool,
}

impl FlowInspector {
    pub(crate) fn new(
        services: DataPlaneServices,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
        protocol: Protocol,
        maximum_inspected_bytes: usize,
    ) -> Self {
        let decision = services.decision_snapshot();
        let client_to_upstream = decision.inspection().scanner(Direction::ClientToUpstream);
        let upstream_to_client = decision.inspection().scanner(Direction::UpstreamToClient);
        let http_request_body = decision.inspection().scanner(Direction::HttpRequestBody);
        let http_response_body = decision.inspection().scanner(Direction::HttpResponseBody);
        let mode = decision.inspection_mode();
        Self {
            services,
            decision,
            session_id,
            transaction_id,
            protocol,
            target: None,
            mode,
            client_to_upstream,
            upstream_to_client,
            http_request_body,
            http_response_body,
            captured_bytes: [0; 4],
            ui_observed_bytes: [0; 4],
            ui_retained_bytes: [0; 4],
            ui_truncation_reported: [false; 4],
            maximum_inspected_bytes,
            inspected_bytes: [0; 4],
        }
    }

    pub(crate) const fn uses_preflight(&self) -> bool {
        matches!(self.mode, InspectionMode::Preflight)
    }

    /// Retains the selected connection only for immutable observer events.
    pub(crate) fn with_target(mut self, target: ResolvedTargetFacts) -> Self {
        self.target = Some(target);
        self
    }

    /// Inspects a chunk and reports whether policy permits forwarding it.
    pub(crate) async fn permits(
        &mut self,
        direction: Direction,
        bytes: &[u8],
    ) -> Result<bool, ProxyError> {
        self.publish_ui_prefix(direction, bytes);
        self.capture(direction, bytes).await?;
        let index = direction_index(direction);
        let remaining = self
            .maximum_inspected_bytes
            .saturating_sub(self.inspected_bytes[index]);
        let count = remaining.min(bytes.len());
        if count == 0 {
            return Ok(true);
        }
        if self.uses_preflight() {
            self.inspected_bytes[index] = self.maximum_inspected_bytes;
        } else {
            self.inspected_bytes[index] = self.inspected_bytes[index].saturating_add(count);
        }
        let inspected = &bytes[..count];
        let findings = match (self.mode, direction) {
            (
                InspectionMode::Preflight | InspectionMode::Streaming,
                Direction::ClientToUpstream,
            ) => self.client_to_upstream.inspect(inspected),
            (
                InspectionMode::Preflight | InspectionMode::Streaming,
                Direction::UpstreamToClient,
            ) => self.upstream_to_client.inspect(inspected),
            (InspectionMode::Preflight | InspectionMode::Streaming, Direction::HttpRequestBody) => {
                self.http_request_body.inspect(inspected)
            }
            (
                InspectionMode::Preflight | InspectionMode::Streaming,
                Direction::HttpResponseBody,
            ) => self.http_response_body.inspect(inspected),
        };
        let context = audit_context(self.session_id, self.transaction_id, &self.services);
        for finding in findings {
            self.services
                .publish_finding(context, finding.clone())
                .await?;
            self.services
                .publish_replay_facts(
                    context,
                    ReplayFacts::Finding {
                        finding: finding.clone(),
                        protocol: self.protocol,
                    },
                )
                .await?;
            let decision = self.decision.inspection().evaluate(&finding, self.protocol);
            self.services
                .publish_inspection_decision(context, decision.clone(), self.target.as_ref())
                .await?;
            if !self.decision.permits(&decision) {
                record_action(
                    self.session_id,
                    self.transaction_id,
                    &self.services,
                    decision,
                )
                .await?;
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn publish_ui_prefix(&mut self, direction: Direction, bytes: &[u8]) {
        let index = direction_index(direction);
        let offset = self.ui_observed_bytes[index];
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        self.ui_observed_bytes[index] = offset.saturating_add(byte_count);
        let Some(settings) = self.services.ui_capture_settings() else {
            return;
        };
        let remaining = settings
            .content_bytes()
            .saturating_sub(self.ui_retained_bytes[index]);
        let retained = remaining.min(bytes.len());
        self.ui_retained_bytes[index] = self.ui_retained_bytes[index].saturating_add(retained);
        let truncated = retained < bytes.len();
        if retained == 0 && (!truncated || self.ui_truncation_reported[index]) {
            return;
        }
        if truncated {
            self.ui_truncation_reported[index] = true;
        }
        self.services.publish_body_prefix(
            self.session_id,
            self.transaction_id,
            direction,
            &bytes[..retained],
            offset,
            self.ui_observed_bytes[index],
            truncated,
        );
    }

    async fn capture(&mut self, direction: Direction, bytes: &[u8]) -> Result<(), ProxyError> {
        let Some(maximum) = self.services.capture_prefix_bytes() else {
            return Ok(());
        };
        let index = direction_index(direction);
        let remaining = maximum.saturating_sub(self.captured_bytes[index]);
        let count = remaining.min(bytes.len());
        if count == 0 {
            return Ok(());
        }
        self.captured_bytes[index] = self.captured_bytes[index].saturating_add(count);
        self.services
            .publish_capture(
                audit_context(self.session_id, self.transaction_id, &self.services),
                direction,
                self.protocol,
                &bytes[..count],
            )
            .await
    }

    pub(crate) async fn transform_tcp_chunk(
        &self,
        direction: Direction,
        bytes: &[u8],
        maximum_replacement_bytes: usize,
    ) -> Result<Option<bytes::Bytes>, ProxyError> {
        let input = bytes::Bytes::copy_from_slice(bytes);
        let context = audit_context(self.session_id, self.transaction_id, &self.services);
        match self
            .services
            .run_tcp_hook(context, direction, input.clone())
            .await?
        {
            ChunkMutationPlan::Keep => Ok(Some(input)),
            ChunkMutationPlan::Replace(replacement)
                if replacement.len() > maximum_replacement_bytes =>
            {
                Err(ProxyError::HookMutation(MutationError::BodyTooLarge {
                    actual: replacement.len(),
                    maximum: maximum_replacement_bytes,
                }))
            }
            ChunkMutationPlan::Replace(replacement) => Ok(Some(replacement)),
            ChunkMutationPlan::Drop => Ok(None),
        }
    }

    pub(crate) async fn transform_http_body(
        &self,
        direction: Direction,
        bytes: bytes::Bytes,
        maximum_replacement_bytes: usize,
        decoded_replacement_allowed: bool,
    ) -> Result<BodyTransform, ProxyError> {
        if self.services.hooks().mode() == freja_domain::HookMode::Disabled {
            return Ok(BodyTransform {
                bytes,
                replaced: false,
            });
        }
        let body = WireBody::new(bytes.clone());
        let (stage, result) = match direction {
            Direction::HttpRequestBody => (
                "http-request-body",
                self.services.hooks().request_body(&body).await,
            ),
            Direction::HttpResponseBody => (
                "http-response-body",
                self.services.hooks().response_body(&body).await,
            ),
            Direction::ClientToUpstream | Direction::UpstreamToClient => {
                return Ok(BodyTransform {
                    bytes,
                    replaced: false,
                });
            }
        };
        let context = audit_context(self.session_id, self.transaction_id, &self.services);
        self.services
            .publish_hook_outcome(context, stage, result.is_ok())
            .await?;
        let automatic_plan = result.map_err(ProxyError::Hook)?;
        let automatic_replaced = matches!(automatic_plan, BodyMutationPlan::Replace(_));
        if automatic_replaced && !decoded_replacement_allowed {
            return Err(ProxyError::HookMutation(
                MutationError::EncodedBodyReplacement,
            ));
        }
        let automatic = apply_body_mutation(&body, &automatic_plan, maximum_replacement_bytes)
            .map_err(ProxyError::HookMutation)?;
        Ok(BodyTransform {
            bytes: automatic,
            replaced: automatic_replaced,
        })
    }
}

const fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::ClientToUpstream => 0,
        Direction::UpstreamToClient => 1,
        Direction::HttpRequestBody => 2,
        Direction::HttpResponseBody => 3,
    }
}
