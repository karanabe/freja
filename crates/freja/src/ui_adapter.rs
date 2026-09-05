use freja_proxy::{DataPlaneEvent, DataPlaneEventSink};
use freja_ui::{UiEvent, UiPublisher};

/// Composition-root adapter from runtime facts to the current presentation.
#[derive(Debug, Clone)]
pub(crate) struct UiDataPlaneEventSink {
    publisher: UiPublisher,
}

impl UiDataPlaneEventSink {
    pub(crate) const fn new(publisher: UiPublisher) -> Self {
        Self { publisher }
    }
}

impl DataPlaneEventSink for UiDataPlaneEventSink {
    fn try_publish(&self, event: DataPlaneEvent) {
        let _outcome = self.publisher.try_publish(to_ui_event(event));
    }

    fn dropped_events(&self) -> u64 {
        self.publisher.dropped_events()
    }
}

#[allow(clippy::too_many_lines)]
fn to_ui_event(event: DataPlaneEvent) -> UiEvent {
    match event {
        DataPlaneEvent::FlowOpened {
            session_id,
            client,
            target,
        } => UiEvent::FlowOpened {
            session_id,
            client,
            target,
        },
        DataPlaneEvent::HttpObserved {
            session_id,
            transaction_id,
            method,
            target,
            version,
            headers,
        } => UiEvent::HttpObserved {
            session_id,
            transaction_id,
            method,
            target,
            version,
            headers,
        },
        DataPlaneEvent::HttpResponseObserved {
            session_id,
            transaction_id,
            status,
            version,
            headers,
        } => UiEvent::HttpResponseObserved {
            session_id,
            transaction_id,
            status,
            version,
            headers,
        },
        DataPlaneEvent::DecisionMade {
            session_id,
            transaction_id,
            trace,
            evidence,
            target,
        } => UiEvent::DecisionMade {
            session_id,
            transaction_id,
            trace,
            evidence,
            target,
        },
        DataPlaneEvent::FindingDetected {
            session_id,
            transaction_id,
            finding,
        } => UiEvent::FindingDetected {
            session_id,
            transaction_id,
            finding,
        },
        DataPlaneEvent::BodyPrefix {
            session_id,
            transaction_id,
            direction,
            bytes,
            offset,
            observed_bytes,
            truncated,
        } => UiEvent::BodyPrefix {
            session_id,
            transaction_id,
            direction,
            bytes,
            offset,
            observed_bytes,
            truncated,
        },
        DataPlaneEvent::WireCaptured {
            session_id,
            transaction_id,
            direction,
            bytes,
            observed_bytes,
            truncated,
        } => UiEvent::WireCaptured {
            session_id,
            transaction_id,
            direction,
            bytes,
            observed_bytes,
            truncated,
        },
        DataPlaneEvent::WireCaptureFailed {
            session_id,
            transaction_id,
            direction,
            reason,
        } => UiEvent::WireCaptureFailed {
            session_id,
            transaction_id,
            direction,
            reason,
        },
        DataPlaneEvent::WireCaptureUnavailable {
            session_id,
            transaction_id,
            direction,
            reason,
        } => UiEvent::WireCaptureUnavailable {
            session_id,
            transaction_id,
            direction,
            reason,
        },
        DataPlaneEvent::FlowClosed {
            session_id,
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        } => UiEvent::FlowClosed {
            session_id,
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        },
    }
}

#[cfg(test)]
mod tests {
    use freja_domain::{
        DecisionTrace, EnforcementActionKind, EvaluationTarget, PolicyGeneration, PolicyStage,
        Port, Protocol, RequestedTargetFacts, SessionId, TargetHost, TransactionId,
    };
    use freja_proxy::{DataPlaneEvent, DataPlaneEventSink as _};
    use freja_ui::{UiEvent, UiPublisher};

    use super::UiDataPlaneEventSink;

    #[test]
    fn evaluation_and_connection_facts_cross_the_adapter_together() {
        let (publisher, mut receiver) = UiPublisher::channel(1).unwrap();
        let sink = UiDataPlaneEventSink::new(publisher);
        let session_id = SessionId::new();
        let transaction_id = Some(TransactionId::new());
        let trace = DecisionTrace {
            policy_generation: PolicyGeneration::default(),
            evaluated_stage: PolicyStage::RequestedDestination,
            matched_rule: None,
            match_reasons: Vec::new(),
            final_action: EnforcementActionKind::Allow,
        };
        let target = Some(EvaluationTarget::Requested(RequestedTargetFacts::new(
            "127.0.0.1".parse().unwrap(),
            TargetHost::Ip("192.0.2.1".parse().unwrap()),
            Port::HTTPS,
            Protocol::Http,
        )));
        let policy = freja_policy::AclPolicy::new(
            PolicyGeneration::default(),
            Vec::new(),
            freja_policy::RuleAction::Allow,
        )
        .unwrap();
        let Some(EvaluationTarget::Requested(requested)) = &target else {
            unreachable!()
        };
        let evidence = Some(
            policy
                .evaluate_with_definition(freja_policy::PolicyFacts::Requested(requested))
                .1
                .snapshot(freja_domain::EnforcementMode::Observe),
        );
        sink.try_publish(DataPlaneEvent::DecisionMade {
            session_id,
            transaction_id,
            trace: trace.clone(),
            evidence: evidence.clone(),
            target: target.clone(),
        });
        assert_eq!(
            receiver.try_recv().unwrap(),
            UiEvent::DecisionMade {
                session_id,
                transaction_id,
                trace,
                evidence,
                target
            }
        );
    }

    #[test]
    fn runtime_events_are_adapted_and_saturation_is_reported() {
        let (publisher, mut receiver) = UiPublisher::channel(1).unwrap();
        let sink = UiDataPlaneEventSink::new(publisher);
        let event = || DataPlaneEvent::FlowClosed {
            session_id: SessionId::new(),
            client_to_upstream_bytes: 1,
            upstream_to_client_bytes: 2,
        };

        sink.try_publish(event());
        assert!(matches!(
            receiver.try_recv(),
            Ok(UiEvent::FlowClosed { .. })
        ));
        sink.try_publish(event());
        sink.try_publish(event());
        assert_eq!(sink.dropped_events(), 1);
    }
}
