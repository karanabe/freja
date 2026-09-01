use std::collections::VecDeque;

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};

use crate::UiEvent;

/// Bounded immutable view of one flow.
#[derive(Debug, Clone)]
pub struct FlowSnapshot {
    /// Connection correlation identity.
    pub session_id: SessionId,
    /// Most recently observed peer description.
    pub client: String,
    /// Most recently observed target description.
    pub target: String,
    /// Bounded request metadata in observation order.
    pub http: VecDeque<HttpSnapshot>,
    /// Bounded findings in observation order.
    pub findings: VecDeque<Finding>,
    /// Bounded policy traces in observation order.
    pub traces: VecDeque<DecisionTrace>,
    /// Bounded copied payload prefixes in observation order.
    pub prefixes: VecDeque<PrefixSnapshot>,
    /// Final client-to-upstream byte count, or zero while unknown.
    pub client_to_upstream_bytes: u64,
    /// Final upstream-to-client byte count, or zero while unknown.
    pub upstream_to_client_bytes: u64,
    /// Whether the terminal flow event has been observed.
    pub closed: bool,
}

/// Request metadata displayed without retaining a live HTTP object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSnapshot {
    /// HTTP exchange correlation identity.
    pub transaction_id: TransactionId,
    /// Normalized HTTP method.
    pub method: String,
    /// Redacted request target.
    pub target: String,
}

/// Bounded body bytes copied for hex/ASCII presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSnapshot {
    /// HTTP exchange identity, or `None` for raw TCP traffic.
    pub transaction_id: Option<TransactionId>,
    /// Logical traffic direction.
    pub direction: Direction,
    /// Bounded copied bytes that may contain sensitive payload data.
    pub bytes: Vec<u8>,
}

/// Reducer state used by both the live terminal and deterministic UI tests.
#[derive(Debug)]
pub struct TuiModel {
    pub(super) flows: VecDeque<FlowSnapshot>,
    pub(super) operational_logs: VecDeque<String>,
    pub(super) selected: usize,
    maximum_flows: usize,
    maximum_items_per_flow: usize,
    pub(super) dropped_events: u64,
    pub(super) paused_flows: usize,
    pub(super) interactive_status: String,
}

impl Default for TuiModel {
    fn default() -> Self {
        Self::new(512, 64)
    }
}

impl TuiModel {
    /// Creates a reducer with explicit retained-flow and per-flow snapshot limits.
    pub fn new(maximum_flows: usize, maximum_items_per_flow: usize) -> Self {
        Self {
            flows: VecDeque::new(),
            operational_logs: VecDeque::new(),
            selected: 0,
            maximum_flows: maximum_flows.max(1),
            maximum_items_per_flow: maximum_items_per_flow.max(1),
            dropped_events: 0,
            paused_flows: 0,
            interactive_status: "idle".to_owned(),
        }
    }

    /// Applies one immutable event without acquiring references to network sessions.
    pub fn apply(&mut self, event: UiEvent) {
        let event = match event {
            UiEvent::OperationalLog { message } => {
                push_bounded(
                    &mut self.operational_logs,
                    message,
                    self.maximum_items_per_flow,
                );
                return;
            }
            event => event,
        };
        let Some(session_id) = event_session_id(&event) else {
            return;
        };
        let index = self.ensure_flow(session_id);
        let maximum_items = self.maximum_items_per_flow;
        let flow = &mut self.flows[index];
        match event {
            UiEvent::FlowOpened { client, target, .. } => {
                flow.client = client;
                flow.target = target;
            }
            UiEvent::HttpObserved {
                transaction_id,
                method,
                target,
                ..
            } => push_bounded(
                &mut flow.http,
                HttpSnapshot {
                    transaction_id,
                    method,
                    target,
                },
                maximum_items,
            ),
            UiEvent::DecisionMade { trace, .. } => {
                push_bounded(&mut flow.traces, trace, maximum_items);
            }
            UiEvent::FindingDetected { finding, .. } => {
                push_bounded(&mut flow.findings, finding, maximum_items);
            }
            UiEvent::BodyPrefix {
                transaction_id,
                direction,
                bytes,
                ..
            } => push_bounded(
                &mut flow.prefixes,
                PrefixSnapshot {
                    transaction_id,
                    direction,
                    bytes,
                },
                maximum_items,
            ),
            UiEvent::FlowClosed {
                client_to_upstream_bytes,
                upstream_to_client_bytes,
                ..
            } => {
                flow.client_to_upstream_bytes = client_to_upstream_bytes;
                flow.upstream_to_client_bytes = upstream_to_client_bytes;
                flow.closed = true;
            }
            UiEvent::OperationalLog { .. } => {}
        }
        self.selected = index;
    }

    /// Moves selection toward the oldest retained flow without underflowing.
    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// Moves selection toward the newest retained flow when one exists.
    pub fn select_next(&mut self) {
        if self.selected.saturating_add(1) < self.flows.len() {
            self.selected += 1;
        }
    }

    /// Replaces the displayed monotonic best-effort delivery counter.
    pub fn set_dropped_events(&mut self, dropped_events: u64) {
        self.dropped_events = dropped_events;
    }

    pub(super) fn set_interactive_state(&mut self, paused_flows: usize, status: String) {
        self.paused_flows = paused_flows;
        self.interactive_status = status;
    }

    /// Returns retained flow snapshots from oldest to newest.
    pub fn flows(&self) -> &VecDeque<FlowSnapshot> {
        &self.flows
    }

    pub(super) fn selected_flow(&self) -> Option<&FlowSnapshot> {
        self.flows.get(self.selected)
    }

    fn ensure_flow(&mut self, session_id: SessionId) -> usize {
        if let Some(index) = self
            .flows
            .iter()
            .position(|flow| flow.session_id == session_id)
        {
            return index;
        }
        if self.flows.len() == self.maximum_flows {
            self.flows.pop_front();
            self.selected = self.selected.saturating_sub(1);
        }
        self.flows.push_back(empty_flow(session_id));
        self.flows.len().saturating_sub(1)
    }
}
fn event_session_id(event: &UiEvent) -> Option<SessionId> {
    match event {
        UiEvent::FlowOpened { session_id, .. }
        | UiEvent::HttpObserved { session_id, .. }
        | UiEvent::DecisionMade { session_id, .. }
        | UiEvent::FindingDetected { session_id, .. }
        | UiEvent::BodyPrefix { session_id, .. }
        | UiEvent::FlowClosed { session_id, .. } => Some(*session_id),
        UiEvent::OperationalLog { .. } => None,
    }
}

fn empty_flow(session_id: SessionId) -> FlowSnapshot {
    FlowSnapshot {
        session_id,
        client: "<unknown>".to_owned(),
        target: "<unknown>".to_owned(),
        http: VecDeque::new(),
        findings: VecDeque::new(),
        traces: VecDeque::new(),
        prefixes: VecDeque::new(),
        client_to_upstream_bytes: 0,
        upstream_to_client_bytes: 0,
        closed: false,
    }
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T, maximum: usize) {
    if queue.len() == maximum {
        queue.pop_front();
    }
    queue.push_back(value);
}
