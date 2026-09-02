use std::collections::VecDeque;

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};
use freja_policy::hook::InterceptRequest;

use crate::UiEvent;

use super::editor::{RequestEditError, RequestEditor};

/// Top-level TUI page selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TuiPage {
    /// Live HTTP transactions and TCP sessions.
    #[default]
    Traffic,
    /// Findings, decision traces, operational logs, and counters.
    Diagnostics,
}

/// Traffic detail layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetailLayout {
    /// Request and response sides each receive half of the width.
    #[default]
    Split,
    /// The request side receives the full detail width.
    Request,
    /// The response side receives the full detail width.
    Response,
}

/// Representation used for the selected traffic side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisplayMode {
    /// Parsed start line, headers, and bounded body.
    #[default]
    Pretty,
    /// Exact retained ingress bytes with terminal controls escaped.
    Raw,
    /// Offset-based hexadecimal and ASCII rows.
    Hex,
}

/// Side selected for focused display and scrolling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectedSide {
    /// HTTP request or client-to-upstream TCP bytes.
    #[default]
    Request,
    /// HTTP response or upstream-to-client TCP bytes.
    Response,
}

/// Pane currently receiving navigation keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FocusPane {
    /// Traffic row list.
    #[default]
    Flows,
    /// Request or response detail.
    Detail,
    /// Findings and decision traces.
    Evidence,
    /// Operational log history.
    Logs,
}

/// Protocol-level unit represented by one Flows row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficKind {
    /// One HTTP exchange identified by `TransactionId`.
    Http,
    /// One TCP connection identified by `SessionId`.
    Tcp,
}

/// Exact wire capture availability for one traffic side.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum WireState {
    /// No complete exact capture has arrived yet.
    #[default]
    Pending,
    /// Exact retained bytes and their full observed length.
    Captured {
        /// Retained message bytes.
        bytes: Vec<u8>,
        /// Full message length before truncation.
        observed_bytes: u64,
        /// Whether the retention limit omitted a suffix.
        truncated: bool,
    },
    /// Capture failed independently of forwarding.
    Failed(String),
    /// This protocol or response origin has no applicable ingress capture.
    Unavailable(String),
}

/// Parsed and raw immutable data for one direction of a traffic row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SideSnapshot {
    /// HTTP start/status line when this is an HTTP row.
    pub start_line: Option<String>,
    /// Parsed HTTP headers in observation order.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Bounded semantic body or exact TCP prefix.
    pub body: Vec<u8>,
    /// Full number of observed body/TCP bytes.
    pub observed_body_bytes: u64,
    /// Whether the bounded body omitted bytes.
    pub body_truncated: bool,
    /// Whether a dropped or reordered event left a gap.
    pub body_incomplete: bool,
    /// Exact HTTP/1 ingress capture state.
    pub wire: WireState,
}

impl SideSnapshot {
    fn append_body(&mut self, offset: u64, bytes: Vec<u8>, observed_bytes: u64, truncated: bool) {
        let retained_length = u64::try_from(self.body.len()).unwrap_or(u64::MAX);
        if offset == retained_length {
            self.body.extend(bytes);
        } else {
            self.body_incomplete = true;
        }
        self.observed_body_bytes = self.observed_body_bytes.max(observed_bytes);
        self.body_truncated |= truncated;
    }
}

/// One HTTP transaction or TCP session shown in the Flows pane.
#[derive(Debug, Clone)]
pub struct TrafficRow {
    /// Connection correlation identity.
    pub session_id: SessionId,
    /// HTTP exchange identity; absent for a TCP row.
    pub transaction_id: Option<TransactionId>,
    /// HTTP exchange or TCP session.
    pub kind: TrafficKind,
    /// Most recently observed peer description.
    pub client: String,
    /// Most recently observed target description.
    pub target: String,
    /// Request/client-to-upstream side.
    pub request: SideSnapshot,
    /// Response/upstream-to-client side.
    pub response: SideSnapshot,
    /// Bounded findings correlated to this row.
    pub findings: VecDeque<Finding>,
    /// Bounded policy traces correlated to this row.
    pub traces: VecDeque<DecisionTrace>,
    /// Final client-to-upstream byte count, or zero while unknown.
    pub client_to_upstream_bytes: u64,
    /// Final upstream-to-client byte count, or zero while unknown.
    pub upstream_to_client_bytes: u64,
    /// Whether the underlying connection closed.
    pub closed: bool,
}

#[derive(Debug, Clone)]
struct SessionMetadata {
    session_id: SessionId,
    client: String,
    target: String,
}

/// Reducer state used by both the live terminal and deterministic UI tests.
#[derive(Debug)]
pub struct TuiModel {
    pub(super) rows: VecDeque<TrafficRow>,
    sessions: Vec<SessionMetadata>,
    pub(super) operational_logs: VecDeque<String>,
    pub(super) selected: usize,
    maximum_rows: usize,
    maximum_items_per_row: usize,
    paused_transactions: Vec<TransactionId>,
    pub(super) page: TuiPage,
    pub(super) layout: DetailLayout,
    pub(super) display_mode: DisplayMode,
    pub(super) selected_side: SelectedSide,
    pub(super) focus: FocusPane,
    pub(super) expanded_pane: Option<FocusPane>,
    pub(super) editor: Option<RequestEditor>,
    pub(super) detail_scroll: u16,
    pub(super) diagnostics_scroll: u16,
    pub(super) log_scroll: u16,
    pub(super) dropped_events: u64,
    pub(super) capture_failures: u64,
    pub(super) capture_truncations: u64,
    pub(super) paused_flows: usize,
    pub(super) interactive_status: String,
    pub(super) input_notice: Option<String>,
}

impl Default for TuiModel {
    fn default() -> Self {
        Self::new(128, 64)
    }
}

impl TuiModel {
    /// Creates a reducer with explicit retained-row and per-row evidence limits.
    pub fn new(maximum_rows: usize, maximum_items_per_row: usize) -> Self {
        Self {
            rows: VecDeque::new(),
            sessions: Vec::new(),
            operational_logs: VecDeque::new(),
            selected: 0,
            maximum_rows: maximum_rows.max(1),
            maximum_items_per_row: maximum_items_per_row.max(1),
            paused_transactions: Vec::new(),
            page: TuiPage::Traffic,
            layout: DetailLayout::Split,
            display_mode: DisplayMode::Pretty,
            selected_side: SelectedSide::Request,
            focus: FocusPane::Flows,
            expanded_pane: None,
            editor: None,
            detail_scroll: 0,
            diagnostics_scroll: 0,
            log_scroll: 0,
            dropped_events: 0,
            capture_failures: 0,
            capture_truncations: 0,
            paused_flows: 0,
            interactive_status: "idle".to_owned(),
            input_notice: None,
        }
    }

    /// Applies one immutable event without retaining a live network object.
    #[allow(clippy::too_many_lines)]
    pub fn apply(&mut self, event: UiEvent) {
        match event {
            UiEvent::OperationalLog { message } => push_bounded(
                &mut self.operational_logs,
                message,
                self.maximum_items_per_row,
            ),
            UiEvent::FlowOpened {
                session_id,
                client,
                target,
            } => self.update_session(session_id, &client, &target),
            UiEvent::HttpObserved {
                session_id,
                transaction_id,
                method,
                target,
                version,
                headers,
            } => {
                let Some(index) = self.ensure_http_row(session_id, transaction_id) else {
                    return;
                };
                let row = &mut self.rows[index];
                row.target.clone_from(&target);
                row.request.start_line = Some(format!("{method} {target} {version}"));
                row.request.headers = headers;
                self.selected = index;
            }
            UiEvent::HttpResponseObserved {
                session_id,
                transaction_id,
                status,
                version,
                headers,
            } => {
                let Some(index) = self.ensure_http_row(session_id, transaction_id) else {
                    return;
                };
                let row = &mut self.rows[index];
                row.response.start_line = Some(response_start_line(&version, status));
                row.response.headers = headers;
                if matches!(row.response.wire, WireState::Pending) {
                    row.response.wire = WireState::Unavailable(
                        "upstream Raw is unavailable for a local or uncaptured response".to_owned(),
                    );
                }
            }
            UiEvent::DecisionMade {
                session_id,
                transaction_id,
                trace,
            } => {
                if let Some(index) = self.ensure_correlated_row(session_id, transaction_id) {
                    push_bounded(
                        &mut self.rows[index].traces,
                        trace,
                        self.maximum_items_per_row,
                    );
                }
            }
            UiEvent::FindingDetected {
                session_id,
                transaction_id,
                finding,
            } => {
                if let Some(index) = self.ensure_correlated_row(session_id, transaction_id) {
                    push_bounded(
                        &mut self.rows[index].findings,
                        finding,
                        self.maximum_items_per_row,
                    );
                }
            }
            UiEvent::BodyPrefix {
                session_id,
                transaction_id,
                direction,
                bytes,
                offset,
                observed_bytes,
                truncated,
            } => {
                let Some(index) = self.ensure_correlated_row(session_id, transaction_id) else {
                    return;
                };
                side_mut(&mut self.rows[index], direction).append_body(
                    offset,
                    bytes,
                    observed_bytes,
                    truncated,
                );
                if truncated {
                    self.capture_truncations = self.capture_truncations.saturating_add(1);
                }
            }
            UiEvent::WireCaptured {
                session_id,
                transaction_id,
                direction,
                bytes,
                observed_bytes,
                truncated,
            } => {
                let Some(index) = self.ensure_http_row(session_id, transaction_id) else {
                    return;
                };
                side_mut(&mut self.rows[index], direction).wire = WireState::Captured {
                    bytes,
                    observed_bytes,
                    truncated,
                };
                if truncated {
                    self.capture_truncations = self.capture_truncations.saturating_add(1);
                }
            }
            UiEvent::WireCaptureFailed {
                session_id,
                transaction_id,
                direction,
                reason,
            } => {
                let Some(index) = self.ensure_http_row(session_id, transaction_id) else {
                    return;
                };
                side_mut(&mut self.rows[index], direction).wire = WireState::Failed(reason);
                self.capture_failures = self.capture_failures.saturating_add(1);
            }
            UiEvent::FlowClosed {
                session_id,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
            } => self.close_session(
                session_id,
                client_to_upstream_bytes,
                upstream_to_client_bytes,
            ),
        }
    }

    /// Selects the Traffic page.
    pub fn show_traffic(&mut self) {
        self.page = TuiPage::Traffic;
        self.focus = FocusPane::Flows;
        self.expanded_pane = None;
    }

    /// Selects the Diagnostics page.
    pub fn show_diagnostics(&mut self) {
        self.page = TuiPage::Diagnostics;
        self.focus = FocusPane::Evidence;
        self.expanded_pane = None;
    }

    /// Cycles split, request-wide, and response-wide traffic details.
    pub fn cycle_layout(&mut self) {
        self.layout = match self.layout {
            DetailLayout::Split => {
                self.selected_side = SelectedSide::Request;
                DetailLayout::Request
            }
            DetailLayout::Request => {
                self.selected_side = SelectedSide::Response;
                DetailLayout::Response
            }
            DetailLayout::Response => DetailLayout::Split,
        };
        self.detail_scroll = 0;
    }

    /// Cycles Pretty, Raw, and Hex representations.
    pub fn cycle_display_mode(&mut self) {
        self.display_mode = match self.display_mode {
            DisplayMode::Pretty => DisplayMode::Raw,
            DisplayMode::Raw => DisplayMode::Hex,
            DisplayMode::Hex => DisplayMode::Pretty,
        };
        self.detail_scroll = 0;
    }

    /// Selects the request/client side.
    pub fn select_request_side(&mut self) {
        self.selected_side = SelectedSide::Request;
        self.detail_scroll = 0;
    }

    /// Selects the response/upstream side.
    pub fn select_response_side(&mut self) {
        self.selected_side = SelectedSide::Response;
        self.detail_scroll = 0;
    }

    /// Cycles focus through the panes available on the active page.
    pub fn cycle_focus(&mut self) {
        self.focus_next();
    }

    /// Moves focus to the next vertically adjacent pane.
    pub fn focus_next(&mut self) {
        self.focus = match (self.page, self.focus) {
            (TuiPage::Traffic, FocusPane::Flows) => FocusPane::Detail,
            (TuiPage::Traffic, _) => FocusPane::Flows,
            (TuiPage::Diagnostics, FocusPane::Evidence) => FocusPane::Logs,
            (TuiPage::Diagnostics, _) => FocusPane::Evidence,
        };
    }

    /// Moves focus to the previous vertically adjacent pane.
    pub fn focus_previous(&mut self) {
        self.focus = match (self.page, self.focus) {
            (TuiPage::Traffic, FocusPane::Detail) => FocusPane::Flows,
            (TuiPage::Traffic, _) => FocusPane::Detail,
            (TuiPage::Diagnostics, FocusPane::Logs) => FocusPane::Evidence,
            (TuiPage::Diagnostics, _) => FocusPane::Logs,
        };
    }

    /// Expands the focused pane into a floating overlay.
    pub fn expand_focused_pane(&mut self) {
        self.expanded_pane = Some(self.focus);
    }

    /// Closes the floating pane overlay.
    pub fn close_expanded_pane(&mut self) {
        self.expanded_pane = None;
    }

    /// Returns the pane currently displayed as a floating overlay.
    pub const fn expanded_pane(&self) -> Option<FocusPane> {
        self.expanded_pane
    }

    /// Moves selection toward the oldest retained row.
    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
        self.detail_scroll = 0;
    }

    /// Moves selection toward the newest retained row.
    pub fn select_next(&mut self) {
        if self.selected.saturating_add(1) < self.rows.len() {
            self.selected += 1;
            self.detail_scroll = 0;
        }
    }

    /// Scrolls the active page upward.
    pub fn scroll_up(&mut self, amount: u16) {
        let value = self.active_scroll_mut();
        *value = value.saturating_sub(amount);
    }

    /// Scrolls the active page downward.
    pub fn scroll_down(&mut self, amount: u16) {
        let value = self.active_scroll_mut();
        *value = value.saturating_add(amount);
    }

    /// Replaces the monotonic best-effort delivery counter.
    pub fn set_dropped_events(&mut self, dropped_events: u64) {
        self.dropped_events = dropped_events;
    }

    pub(super) fn set_interactive_state(
        &mut self,
        paused_transactions: Vec<TransactionId>,
        status: String,
    ) {
        self.paused_flows = paused_transactions.len();
        self.paused_transactions = paused_transactions;
        self.interactive_status = status;
    }

    pub(super) fn apply_intercept_request(&mut self, request: &InterceptRequest) {
        let transaction_id = request.context.transaction_id;
        let snapshot = &request.request;
        if !self.paused_transactions.contains(&transaction_id) {
            self.paused_transactions.push(transaction_id);
        }
        let method = snapshot.method.as_str().to_owned();
        let target = snapshot.uri.to_string();
        let version = format!("{:?}", snapshot.version);
        let headers = snapshot
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        let body = snapshot.body.bytes().to_vec();
        let Some(index) = self.ensure_paused_http_row(request.context.session_id, transaction_id)
        else {
            return;
        };
        let row = &mut self.rows[index];
        row.request.start_line = Some(format!("{method} {target} {version}"));
        row.target = target;
        row.request.headers = headers;
        let body_length = u64::try_from(body.len()).unwrap_or(u64::MAX);
        row.request.body = body;
        row.request.observed_body_bytes = body_length;
        row.request.body_incomplete = false;
        row.request.body_truncated = false;
        self.selected = index;
    }

    pub(super) fn open_request_editor(
        &mut self,
        request: &InterceptRequest,
    ) -> Result<(), RequestEditError> {
        self.editor = Some(RequestEditor::new(&request.request)?);
        Ok(())
    }

    pub(super) fn set_input_notice(&mut self, notice: String) {
        self.input_notice = Some(notice);
    }

    pub(super) fn clear_input_notice(&mut self) {
        self.input_notice = None;
    }

    pub(super) fn apply_edited_request(&mut self, headers: Vec<(String, Vec<u8>)>, body: Vec<u8>) {
        let Some(row) = self.rows.get_mut(self.selected) else {
            return;
        };
        row.request.headers = headers;
        row.request.observed_body_bytes = u64::try_from(body.len()).unwrap_or(u64::MAX);
        row.request.body = body;
        row.request.body_incomplete = false;
        row.request.body_truncated = false;
    }

    /// Returns retained traffic rows from oldest to newest.
    pub fn rows(&self) -> &VecDeque<TrafficRow> {
        &self.rows
    }

    pub(super) fn selected_row(&self) -> Option<&TrafficRow> {
        self.rows.get(self.selected)
    }

    pub(super) fn selected_transaction_id(&self) -> Option<TransactionId> {
        self.selected_row().and_then(|row| row.transaction_id)
    }

    pub(super) fn selected_is_paused(&self) -> bool {
        self.selected_transaction_id()
            .is_some_and(|id| self.transaction_is_paused(id))
    }

    pub(super) fn transaction_is_paused(&self, transaction_id: TransactionId) -> bool {
        self.paused_transactions.contains(&transaction_id)
    }

    fn active_scroll_mut(&mut self) -> &mut u16 {
        match self.focus {
            FocusPane::Logs => &mut self.log_scroll,
            FocusPane::Flows | FocusPane::Detail => &mut self.detail_scroll,
            FocusPane::Evidence => &mut self.diagnostics_scroll,
        }
    }

    fn update_session(&mut self, session_id: SessionId, client: &str, target: &str) {
        if let Some(metadata) = self
            .sessions
            .iter_mut()
            .find(|metadata| metadata.session_id == session_id)
        {
            client.clone_into(&mut metadata.client);
            target.clone_into(&mut metadata.target);
        } else {
            self.sessions.push(SessionMetadata {
                session_id,
                client: client.to_owned(),
                target: target.to_owned(),
            });
        }
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.session_id == session_id)
        {
            client.clone_into(&mut row.client);
            if row.kind == TrafficKind::Tcp {
                target.clone_into(&mut row.target);
            }
        }
    }

    fn ensure_correlated_row(
        &mut self,
        session_id: SessionId,
        transaction_id: Option<TransactionId>,
    ) -> Option<usize> {
        match transaction_id {
            Some(transaction_id) => self.ensure_http_row(session_id, transaction_id),
            None => self.ensure_tcp_row(session_id),
        }
    }

    fn ensure_http_row(
        &mut self,
        session_id: SessionId,
        transaction_id: TransactionId,
    ) -> Option<usize> {
        if let Some(index) = self.rows.iter().position(|row| {
            row.session_id == session_id && row.transaction_id == Some(transaction_id)
        }) {
            return Some(index);
        }
        self.push_row(empty_row(
            session_id,
            Some(transaction_id),
            TrafficKind::Http,
            self.session_metadata(session_id),
        ))
    }

    fn ensure_paused_http_row(
        &mut self,
        session_id: SessionId,
        transaction_id: TransactionId,
    ) -> Option<usize> {
        if let Some(index) = self.rows.iter().position(|row| {
            row.session_id == session_id && row.transaction_id == Some(transaction_id)
        }) {
            return Some(index);
        }
        if self.rows.len() == self.maximum_rows {
            let removable = self.rows.iter().position(|candidate| {
                candidate
                    .transaction_id
                    .is_none_or(|id| !self.paused_transactions.contains(&id))
            })?;
            self.rows.remove(removable);
            if self.selected > removable {
                self.selected = self.selected.saturating_sub(1);
            }
        }
        self.rows.push_back(empty_row(
            session_id,
            Some(transaction_id),
            TrafficKind::Http,
            self.session_metadata(session_id),
        ));
        Some(self.rows.len().saturating_sub(1))
    }

    fn ensure_tcp_row(&mut self, session_id: SessionId) -> Option<usize> {
        if let Some(index) = self
            .rows
            .iter()
            .position(|row| row.session_id == session_id && row.transaction_id.is_none())
        {
            return Some(index);
        }
        self.push_row(empty_row(
            session_id,
            None,
            TrafficKind::Tcp,
            self.session_metadata(session_id),
        ))
    }

    fn session_metadata(&self, session_id: SessionId) -> Option<(String, String)> {
        self.sessions
            .iter()
            .find(|metadata| metadata.session_id == session_id)
            .map(|metadata| (metadata.client.clone(), metadata.target.clone()))
    }

    fn push_row(&mut self, row: TrafficRow) -> Option<usize> {
        if self.rows.len() == self.maximum_rows {
            let removable = self.rows.iter().position(|candidate| {
                candidate.closed
                    && candidate
                        .transaction_id
                        .is_none_or(|id| !self.paused_transactions.contains(&id))
            });
            let index = removable?;
            self.rows.remove(index);
            if self.selected > index {
                self.selected = self.selected.saturating_sub(1);
            }
        }
        self.rows.push_back(row);
        Some(self.rows.len().saturating_sub(1))
    }

    fn close_session(
        &mut self,
        session_id: SessionId,
        client_to_upstream_bytes: u64,
        upstream_to_client_bytes: u64,
    ) {
        let mut matched = false;
        for row in self
            .rows
            .iter_mut()
            .filter(|row| row.session_id == session_id)
        {
            matched = true;
            row.client_to_upstream_bytes = client_to_upstream_bytes;
            row.upstream_to_client_bytes = upstream_to_client_bytes;
            row.closed = true;
        }
        if !matched && let Some(index) = self.ensure_tcp_row(session_id) {
            let row = &mut self.rows[index];
            row.client_to_upstream_bytes = client_to_upstream_bytes;
            row.upstream_to_client_bytes = upstream_to_client_bytes;
            row.closed = true;
        }
        self.sessions
            .retain(|metadata| metadata.session_id != session_id);
    }
}

fn response_start_line(version: &str, status: u16) -> String {
    http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .map_or_else(
            || format!("{version} {status}"),
            |reason| format!("{version} {status} {reason}"),
        )
}

fn empty_row(
    session_id: SessionId,
    transaction_id: Option<TransactionId>,
    kind: TrafficKind,
    metadata: Option<(String, String)>,
) -> TrafficRow {
    let (client, target) =
        metadata.unwrap_or_else(|| ("<unknown>".to_owned(), "<unknown>".to_owned()));
    let tcp_wire = WireState::Unavailable("TCP Raw uses the bounded body stream".to_owned());
    TrafficRow {
        session_id,
        transaction_id,
        kind,
        client,
        target,
        request: SideSnapshot {
            wire: if kind == TrafficKind::Tcp {
                tcp_wire.clone()
            } else {
                WireState::Pending
            },
            ..SideSnapshot::default()
        },
        response: SideSnapshot {
            wire: if kind == TrafficKind::Tcp {
                tcp_wire
            } else {
                WireState::Pending
            },
            ..SideSnapshot::default()
        },
        findings: VecDeque::new(),
        traces: VecDeque::new(),
        client_to_upstream_bytes: 0,
        upstream_to_client_bytes: 0,
        closed: false,
    }
}

fn side_mut(row: &mut TrafficRow, direction: Direction) -> &mut SideSnapshot {
    match direction {
        Direction::ClientToUpstream | Direction::HttpRequestBody => &mut row.request,
        Direction::UpstreamToClient | Direction::HttpResponseBody => &mut row.response,
    }
}

fn push_bounded<T>(queue: &mut VecDeque<T>, value: T, maximum: usize) {
    if queue.len() == maximum {
        queue.pop_front();
    }
    queue.push_back(value);
}
