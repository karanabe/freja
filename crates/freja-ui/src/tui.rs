//! ratatui presentation driven exclusively by immutable [`UiEvent`] snapshots.

use std::{collections::VecDeque, error::Error, fmt, io, thread, time::Duration};

use freja_domain::{DecisionTrace, Direction, Finding, SessionId, TransactionId};
use freja_policy::hook::{
    DecodedBody, HeadMutationPlan, HeaderMutation, InteractiveDecision, InterceptRequest,
};
use http::{HeaderName, HeaderValue};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};
use tokio::sync::{mpsc, oneshot};

use crate::{UiEvent, UiMetrics};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Bounded immutable view of one flow.
#[derive(Debug, Clone)]
pub struct FlowSnapshot {
    pub session_id: SessionId,
    pub client: String,
    pub target: String,
    pub http: VecDeque<HttpSnapshot>,
    pub findings: VecDeque<Finding>,
    pub traces: VecDeque<DecisionTrace>,
    pub prefixes: VecDeque<PrefixSnapshot>,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
    pub closed: bool,
}

/// Request metadata displayed without retaining a live HTTP object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSnapshot {
    pub transaction_id: TransactionId,
    pub method: String,
    pub target: String,
}

/// Bounded body bytes copied for hex/ASCII presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixSnapshot {
    pub transaction_id: Option<TransactionId>,
    pub direction: Direction,
    pub bytes: Vec<u8>,
}

/// Reducer state used by both the live terminal and deterministic UI tests.
#[derive(Debug)]
pub struct TuiModel {
    flows: VecDeque<FlowSnapshot>,
    operational_logs: VecDeque<String>,
    selected: usize,
    maximum_flows: usize,
    maximum_items_per_flow: usize,
    dropped_events: u64,
    paused_flows: usize,
    interactive_status: String,
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

    pub fn select_previous(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn select_next(&mut self) {
        if self.selected.saturating_add(1) < self.flows.len() {
            self.selected += 1;
        }
    }

    pub fn set_dropped_events(&mut self, dropped_events: u64) {
        self.dropped_events = dropped_events;
    }

    fn set_interactive_state(&mut self, paused_flows: usize, status: String) {
        self.paused_flows = paused_flows;
        self.interactive_status = status;
    }

    pub fn flows(&self) -> &VecDeque<FlowSnapshot> {
        &self.flows
    }

    fn selected_flow(&self) -> Option<&FlowSnapshot> {
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

/// Terminal setup, rendering, or input failure.
#[derive(Debug)]
pub enum TuiError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    ThreadSpawn(io::Error),
}

impl fmt::Display for TuiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, .. } => write!(formatter, "TUI {operation} failed"),
            Self::ThreadSpawn(_) => formatter.write_str("failed to spawn dedicated TUI thread"),
        }
    }
}

impl Error for TuiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::ThreadSpawn(source) => Some(source),
        }
    }
}

/// Spawns the terminal owner on a dedicated OS thread.
///
/// # Errors
///
/// Returns [`TuiError::ThreadSpawn`] when the operating system cannot create
/// the dedicated terminal thread.
pub fn spawn_tui(
    receiver: mpsc::Receiver<UiEvent>,
    metrics: UiMetrics,
    intercept_receiver: Option<mpsc::Receiver<InterceptRequest>>,
) -> Result<TuiTask, TuiError> {
    let (exit_sender, exit_receiver) = oneshot::channel();
    let thread = thread::Builder::new()
        .name("freja-tui".to_owned())
        .spawn(move || {
            let result = run_tui(receiver, &metrics, intercept_receiver);
            let _send_result = exit_sender.send(());
            result
        })
        .map_err(TuiError::ThreadSpawn)?;
    Ok(TuiTask {
        exit_receiver,
        thread,
    })
}

/// Join and exit handles for the dedicated terminal owner.
pub struct TuiTask {
    exit_receiver: oneshot::Receiver<()>,
    thread: thread::JoinHandle<Result<(), TuiError>>,
}

impl TuiTask {
    /// Splits the task into an async exit notification and an OS-thread handle.
    pub fn into_parts(
        self,
    ) -> (
        oneshot::Receiver<()>,
        thread::JoinHandle<Result<(), TuiError>>,
    ) {
        (self.exit_receiver, self.thread)
    }
}

/// Runs the terminal event loop until `q`, Escape, or producer shutdown.
///
/// # Errors
///
/// Returns [`TuiError::Io`] when terminal setup, drawing, or input polling fails.
pub fn run_tui(
    mut receiver: mpsc::Receiver<UiEvent>,
    metrics: &UiMetrics,
    mut intercept_receiver: Option<mpsc::Receiver<InterceptRequest>>,
) -> Result<(), TuiError> {
    let mut terminal = TerminalGuard::enter()?;
    let mut model = TuiModel::default();
    let mut pending = VecDeque::new();
    let mut editor = None;
    loop {
        let mut disconnected = false;
        loop {
            match receiver.try_recv() {
                Ok(event) => model.apply(event),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        drain_intercepts(&mut intercept_receiver, &mut pending);
        model.set_dropped_events(metrics.dropped_events());
        model.set_interactive_state(pending.len(), editor_status(&pending, editor.as_ref()));
        terminal.draw(&model)?;
        if disconnected || handle_input(&mut model, &mut pending, &mut editor)? {
            return Ok(());
        }
    }
}

/// Renders flow list, details, decision/finding evidence, and statistics.
pub fn render(frame: &mut Frame<'_>, model: &TuiModel) {
    let rows = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
        .split(frame.area());
    let top = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(rows[0]);
    let bottom = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(rows[1]);
    let diagnostics = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(bottom[0]);
    render_flows(frame, model, top[0]);
    render_details(frame, model, top[1]);
    render_evidence(frame, model, diagnostics[0]);
    render_operational_logs(frame, model, diagnostics[1]);
    render_stats(frame, model, bottom[1]);
}

fn render_flows(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let items = model.flows.iter().enumerate().map(|(index, flow)| {
        let marker = if index == model.selected { ">" } else { " " };
        let state = if flow.closed { "closed" } else { "live" };
        ListItem::new(format!(
            "{marker} {state} {} {}",
            flow.session_id, flow.target
        ))
    });
    frame.render_widget(
        List::new(items).block(Block::default().title("Flows").borders(Borders::ALL)),
        area,
    );
}

fn render_details(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let lines = model.selected_flow().map_or_else(
        || vec![Line::from("No flows")],
        |flow| {
            let mut lines = vec![
                Line::from(format!("client: {}", flow.client)),
                Line::from(format!("target: {}", flow.target)),
            ];
            for http in &flow.http {
                lines.push(Line::from(format!(
                    "{} {} [{}]",
                    http.method, http.target, http.transaction_id
                )));
            }
            for prefix in &flow.prefixes {
                lines.push(Line::from(format!(
                    "{:?}: {}",
                    prefix.direction,
                    hex_ascii(&prefix.bytes)
                )));
            }
            lines
        },
    );
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("HTTP / Prefix")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_evidence(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let lines = model.selected_flow().map_or_else(Vec::new, |flow| {
        let findings = flow.findings.iter().map(|finding| {
            Line::styled(
                format!(
                    "finding {} {:?} {:?}",
                    finding.detector_id, finding.severity, finding.direction
                ),
                Style::default().fg(Color::Yellow),
            )
        });
        let traces = flow.traces.iter().map(|trace| {
            Line::from(format!(
                "decision {:?} rule={} generation={}",
                trace.final_action,
                trace
                    .matched_rule
                    .as_ref()
                    .map_or("<default>", |id| id.as_str()),
                trace.policy_generation
            ))
        });
        findings.chain(traces).collect()
    });
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Findings / DecisionTrace")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_operational_logs(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let visible_lines = usize::from(area.height.saturating_sub(2));
    let first_visible = model.operational_logs.len().saturating_sub(visible_lines);
    let lines = model
        .operational_logs
        .iter()
        .skip(first_visible)
        .map(|message| Line::from(message.as_str()))
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Operational logs")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_stats(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let closed = model.flows.iter().filter(|flow| flow.closed).count();
    let (client_bytes, upstream_bytes) = model.flows.iter().fold((0_u64, 0_u64), |total, flow| {
        (
            total.0.saturating_add(flow.client_to_upstream_bytes),
            total.1.saturating_add(flow.upstream_to_client_bytes),
        )
    });
    let lines = vec![
        Line::from(format!("flows: {} (closed {closed})", model.flows.len())),
        Line::from(format!("bytes: {client_bytes} / {upstream_bytes}")),
        Line::from(format!("UI events dropped: {}", model.dropped_events)),
        Line::from(format!("paused: {}", model.paused_flows)),
        Line::from(format!("interactive: {}", model.interactive_status)),
        Line::from("c continue | r reject | e header | b body | x cancel"),
        Line::from("q / Esc: close UI"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("Statistics").borders(Borders::ALL)),
        area,
    );
}

fn handle_input(
    model: &mut TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
    editor: &mut Option<Editor>,
) -> Result<bool, TuiError> {
    if !event::poll(EVENT_POLL_INTERVAL).map_err(|source| TuiError::Io {
        operation: "input poll",
        source,
    })? {
        return Ok(false);
    }
    let event = event::read().map_err(|source| TuiError::Io {
        operation: "input read",
        source,
    })?;
    let Event::Key(key) = event else {
        return Ok(false);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }
    if editor.is_some() {
        return Ok(handle_editor_key(key.code, pending, editor));
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Ok(true),
        KeyCode::Up | KeyCode::Char('k') => {
            model.select_previous();
            Ok(false)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.select_next();
            Ok(false)
        }
        KeyCode::Char('c') => {
            respond_front(pending, InteractiveDecision::Continue);
            Ok(false)
        }
        KeyCode::Char('r') => {
            respond_front(pending, InteractiveDecision::Reject);
            Ok(false)
        }
        KeyCode::Char('x') => {
            respond_front(pending, InteractiveDecision::CancelModification);
            Ok(false)
        }
        KeyCode::Char('e') if !pending.is_empty() => {
            *editor = Some(Editor::Header(String::new()));
            Ok(false)
        }
        KeyCode::Char('b') if !pending.is_empty() => {
            *editor = Some(Editor::Body(String::new()));
            Ok(false)
        }
        _ => Ok(false),
    }
}

enum Editor {
    Header(String),
    Body(String),
}

const MAXIMUM_MANUAL_BODY_BYTES: usize = 4 * 1_024;
const MAXIMUM_HEADER_INPUT_BYTES: usize = 8 * 1_024;

fn handle_editor_key(
    key: KeyCode,
    pending: &mut VecDeque<InterceptRequest>,
    editor_slot: &mut Option<Editor>,
) -> bool {
    match key {
        KeyCode::Esc => *editor_slot = None,
        KeyCode::Backspace => match editor_slot.as_mut() {
            Some(Editor::Header(value) | Editor::Body(value)) => {
                value.pop();
            }
            None => {}
        },
        KeyCode::Enter => {
            let decision = match editor_slot.as_ref() {
                Some(Editor::Header(value)) => parse_header_decision(value),
                Some(Editor::Body(value)) => Some(InteractiveDecision::ReplaceBody(
                    DecodedBody::new(value.clone()),
                )),
                None => None,
            };
            if let Some(decision) = decision {
                respond_front(pending, decision);
                *editor_slot = None;
            }
        }
        KeyCode::Char(character) => {
            let Some(editor) = editor_slot.as_mut() else {
                return false;
            };
            let maximum = match editor {
                Editor::Header(_) => MAXIMUM_HEADER_INPUT_BYTES,
                Editor::Body(_) => MAXIMUM_MANUAL_BODY_BYTES,
            };
            let value = match editor {
                Editor::Header(value) | Editor::Body(value) => value,
            };
            if value.len().saturating_add(character.len_utf8()) <= maximum {
                value.push(character);
            }
        }
        _ => {}
    }
    false
}

fn parse_header_decision(value: &str) -> Option<InteractiveDecision> {
    let (name, value) = value.split_once(':')?;
    let name = name.trim().parse::<HeaderName>().ok()?;
    let value = value.trim().parse::<HeaderValue>().ok()?;
    Some(InteractiveDecision::EditHeaders(HeadMutationPlan {
        headers: vec![HeaderMutation::Set { name, value }],
    }))
}

fn respond_front(pending: &mut VecDeque<InterceptRequest>, decision: InteractiveDecision) {
    if let Some(request) = pending.pop_front() {
        let _response_result = request.response.send(decision);
    }
}

fn drain_intercepts(
    receiver: &mut Option<mpsc::Receiver<InterceptRequest>>,
    pending: &mut VecDeque<InterceptRequest>,
) {
    let Some(active) = receiver.as_mut() else {
        return;
    };
    let mut disconnected = false;
    loop {
        match active.try_recv() {
            Ok(request) => pending.push_back(request),
            Err(mpsc::error::TryRecvError::Empty) => break,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }
    if disconnected {
        *receiver = None;
    }
}

fn editor_status(pending: &VecDeque<InterceptRequest>, editor: Option<&Editor>) -> String {
    match editor {
        Some(Editor::Header(value)) => format!("header name:value > {value}"),
        Some(Editor::Body(value)) => format!("body ({}/4096) > {value}", value.len()),
        None => pending.front().map_or_else(
            || "idle".to_owned(),
            |request| format!("{:?} {}", request.stage, request.context.session_id),
        ),
    }
}

struct TerminalGuard {
    terminal: DefaultTerminal,
}

impl TerminalGuard {
    fn enter() -> Result<Self, TuiError> {
        match ratatui::try_init() {
            Ok(terminal) => Ok(Self { terminal }),
            Err(source) => {
                let _restore_result = ratatui::try_restore();
                Err(TuiError::Io {
                    operation: "initialization",
                    source,
                })
            }
        }
    }

    fn draw(&mut self, model: &TuiModel) -> Result<(), TuiError> {
        self.terminal
            .draw(|frame| render(frame, model))
            .map(|_| ())
            .map_err(|source| TuiError::Io {
                operation: "draw",
                source,
            })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _restore_result = ratatui::try_restore();
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

fn hex_ascii(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let ascii = bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect::<String>();
    format!("{hex}  |{ascii}|")
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::{TuiModel, hex_ascii, render};
    use crate::UiEvent;
    use freja_domain::SessionId;

    #[test]
    fn immutable_events_reduce_and_render_on_test_backend() {
        let session_id = SessionId::new();
        let mut model = TuiModel::new(4, 4);
        model.apply(UiEvent::FlowOpened {
            session_id,
            client: "127.0.0.1:40000".to_owned(),
            target: "example.test:443".to_owned(),
        });
        model.apply(UiEvent::FlowClosed {
            session_id,
            client_to_upstream_bytes: 10,
            upstream_to_client_bytes: 20,
        });
        model.apply(UiEvent::OperationalLog {
            message: "listener bound without terminal writes".to_owned(),
        });

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| render(frame, &model)).unwrap();

        assert_eq!(model.flows().len(), 1);
        assert!(model.flows()[0].closed);
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<Vec<_>>()
            .join("");
        assert!(rendered.contains("listener bound without terminal writes"));
        assert_eq!(hex_ascii(b"A\0"), "41 00  |A.|");
    }
}
