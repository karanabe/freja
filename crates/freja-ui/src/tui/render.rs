use std::fmt::Write;

use ratatui::{
    Frame,
    buffer::CellWidth,
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};

use super::{
    DetailLayout, DisplayMode, FocusPane, SelectedSide, SideSnapshot, TrafficKind, TrafficRow,
    TuiModel, TuiPage, WireState,
};

mod evidence;
use evidence::{render_evidence, render_rule_detail};

const MINIMUM_WIDTH: u16 = 80;
const MINIMUM_HEIGHT: u16 = 24;

/// Renders the active Traffic or Diagnostics page.
pub fn render(frame: &mut Frame<'_>, model: &TuiModel) {
    if frame.area().width < MINIMUM_WIDTH || frame.area().height < MINIMUM_HEIGHT {
        render_minimum_size(frame);
        return;
    }
    match model.page {
        TuiPage::Traffic => render_traffic(frame, model),
        TuiPage::Diagnostics => render_diagnostics(frame, model),
        TuiPage::Repeat => render_repeat(frame, model),
    }
    if let Some(pane) = model.expanded_pane {
        render_expanded_pane(frame, model, pane);
    }
    if model.evidence_view.detail.is_some() {
        render_rule_detail(frame, model);
    }
    if model.editor.is_some() {
        render_request_editor(frame, model);
    }
}

fn render_minimum_size(frame: &mut Frame<'_>) {
    let area = frame.area();
    let message = format!(
        "Freja TUI requires at least {MINIMUM_WIDTH}x{MINIMUM_HEIGHT}; current size is {}x{}",
        area.width, area.height
    );
    frame.render_widget(
        Paragraph::new(message)
            .block(
                Block::default()
                    .title("Terminal too small")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_traffic(frame: &mut Frame<'_>, model: &TuiModel) {
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(frame.area());
    render_flows(frame, model, areas[0]);
    match model.layout {
        DetailLayout::Split => {
            let details = Layout::default()
                .direction(LayoutDirection::Horizontal)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(areas[1]);
            render_side(frame, model, SelectedSide::Request, details[0]);
            render_side(frame, model, SelectedSide::Response, details[1]);
        }
        DetailLayout::Request => render_side(frame, model, SelectedSide::Request, areas[1]),
        DetailLayout::Response => render_side(frame, model, SelectedSide::Response, areas[1]),
    }
}

fn render_flows(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let items = model.rows.iter().map(|row| {
        let state = if row
            .transaction_id
            .is_some_and(|id| model.transaction_is_paused(id))
        {
            "paused"
        } else if row.closed {
            "closed"
        } else {
            "live"
        };
        let identity = row.transaction_id.map_or_else(
            || row.session_id.to_string(),
            |transaction_id| transaction_id.to_string(),
        );
        let protocol = match row.kind {
            TrafficKind::Http => "HTTP",
            TrafficKind::Tcp => "TCP ",
        };
        let summary = row
            .request
            .start_line
            .as_deref()
            .unwrap_or(row.target.as_str());
        ListItem::new(format!("{protocol} {state:6} {identity} {summary}"))
    });
    let title = format!(
        "Flows [1 Traffic]  mode={:?} layout={:?}  Ctrl+j/k pane | Enter expand",
        model.display_mode, model.layout
    );
    let border_style = if model.focus == FocusPane::Flows {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let list = List::new(items)
        .highlight_symbol("> ")
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .title(title)
                .title_style(Style::default().fg(Color::Yellow))
                .border_style(border_style)
                .borders(Borders::ALL),
        );
    let mut state =
        ListState::default().with_selected(model.selected_row().map(|_| model.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_side(frame: &mut Frame<'_>, model: &TuiModel, selected: SelectedSide, area: Rect) {
    let Some(row) = model.selected_row() else {
        frame.render_widget(
            Paragraph::new("No traffic rows")
                .block(Block::default().title("Traffic").borders(Borders::ALL)),
            area,
        );
        return;
    };
    let side = match selected {
        SelectedSide::Request => &row.request,
        SelectedSide::Response => &row.response,
    };
    let title = side_title(row, selected, model.display_mode);
    let border_style = if model.focus == FocusPane::Detail && model.selected_side == selected {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(side_lines(side, row.kind, model.display_mode))
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(border_style),
            )
            .wrap(Wrap { trim: false })
            .scroll((model.detail_scroll, 0)),
        area,
    );
}

fn side_title(row: &TrafficRow, side: SelectedSide, mode: DisplayMode) -> String {
    let side_name = match (row.kind, side) {
        (TrafficKind::Http, SelectedSide::Request) => "Request",
        (TrafficKind::Http, SelectedSide::Response) => "Response",
        (TrafficKind::Tcp, SelectedSide::Request) => "Client -> Upstream",
        (TrafficKind::Tcp, SelectedSide::Response) => "Upstream -> Client",
    };
    format!("{side_name} [{mode:?}]  m mode | v split/request/response | h/l side")
}

fn render_expanded_pane(frame: &mut Frame<'_>, model: &TuiModel, pane: FocusPane) {
    let area = floating_area(frame.area(), 94, 92);
    frame.render_widget(Clear, area);
    match pane {
        FocusPane::Flows => render_flows(frame, model, area),
        FocusPane::Detail => render_side(frame, model, model.selected_side, area),
        FocusPane::Evidence => render_evidence(frame, model, area),
        FocusPane::Logs => render_operational_logs(frame, model, area),
        FocusPane::RepeatWorkspaces => render_repeat_workspaces(frame, model, area),
        FocusPane::RepeatDetail => {
            render_repeat_side(frame, model, model.selected_side, area);
        }
    }
}

fn render_repeat(frame: &mut Frame<'_>, model: &TuiModel) {
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Percentage(25), Constraint::Percentage(75)])
        .split(frame.area());
    render_repeat_workspaces(frame, model, areas[0]);
    let details = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(areas[1]);
    render_repeat_side(frame, model, SelectedSide::Request, details[0]);
    render_repeat_side(frame, model, SelectedSide::Response, details[1]);
}

fn render_repeat_workspaces(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let items = model.repeat_workspaces.iter().map(|workspace| {
        let status = if workspace.in_flight {
            "sending"
        } else if workspace.latest_result.is_some() {
            "complete"
        } else {
            "ready"
        };
        ListItem::new(format!(
            "{status:8} {} {} {}",
            workspace.source.transaction_id, workspace.request.method, workspace.request.uri
        ))
    });
    let border_style = if model.focus == FocusPane::RepeatWorkspaces {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let list = List::new(items)
        .highlight_symbol("> ")
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .title(format!(
                    "Workspaces [3 Repeat]  s send | e/i edit+send | d delete | q back — {}",
                    escape_terminal_bytes(model.interactive_status.as_bytes())
                ))
                .title_style(Style::default().fg(Color::Yellow))
                .border_style(border_style)
                .borders(Borders::ALL),
        );
    let mut state = ListState::default().with_selected(
        model
            .selected_repeat_workspace()
            .map(|_| model.repeat_selected),
    );
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_repeat_side(frame: &mut Frame<'_>, model: &TuiModel, selected: SelectedSide, area: Rect) {
    let side = match selected {
        SelectedSide::Request => model.repeat_request_side(),
        SelectedSide::Response => model.repeat_response_side(),
    };
    let Some(side) = side else {
        frame.render_widget(
            Paragraph::new("No repeat workspaces")
                .block(Block::default().title("Repeat").borders(Borders::ALL)),
            area,
        );
        return;
    };
    let name = match selected {
        SelectedSide::Request => "Editable request",
        SelectedSide::Response => "Latest result",
    };
    let border_style = if model.focus == FocusPane::RepeatDetail && model.selected_side == selected
    {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(side_lines(&side, TrafficKind::Http, model.display_mode))
            .block(
                Block::default()
                    .title(format!(
                        "{name} [{:?}]  Ctrl+j/k pane | j/k scroll",
                        model.display_mode
                    ))
                    .borders(Borders::ALL)
                    .border_style(border_style),
            )
            .wrap(Wrap { trim: false })
            .scroll((model.detail_scroll, 0)),
        area,
    );
}

fn render_request_editor(frame: &mut Frame<'_>, model: &TuiModel) {
    let Some(editor) = model.editor.as_ref() else {
        return;
    };
    let area = floating_area(frame.area(), 96, 94);
    frame.render_widget(Clear, area);
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(3)])
        .split(area);
    let visible_columns = areas[0].width.saturating_sub(2);
    let visible_rows = areas[0].height.saturating_sub(2);
    let layout = editor_layout(editor, visible_columns);
    let scroll = editor.keep_cursor_visible(layout.cursor_row, visible_rows);
    frame.render_widget(
        Paragraph::new(layout.lines)
            .block(
                Block::default()
                    .title(format!("HTTP/1.1 Request Editor [{:?}]", editor.mode()))
                    .title_style(Style::default().fg(Color::Yellow))
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .scroll((scroll, 0)),
        areas[0],
    );
    frame.render_widget(
        Paragraph::new(editor.status()).block(
            Block::default()
                .title("Typed edit — start line and framing headers are protected")
                .borders(Borders::ALL),
        ),
        areas[1],
    );
    if visible_columns > 0
        && visible_rows > 0
        && layout.cursor_row >= scroll
        && layout.cursor_row < scroll.saturating_add(visible_rows)
    {
        frame.set_cursor_position((
            areas[0]
                .x
                .saturating_add(1)
                .saturating_add(layout.cursor_column),
            areas[0]
                .y
                .saturating_add(1)
                .saturating_add(layout.cursor_row.saturating_sub(scroll)),
        ));
    }
}

struct EditorLayout {
    lines: Vec<Line<'static>>,
    cursor_row: u16,
    cursor_column: u16,
}

/// Wraps the escaped draft independently from the terminal caret so moving the
/// caret cannot add a display cell or change an existing row boundary.
fn editor_layout(editor: &super::editor::RequestEditor, width: u16) -> EditorLayout {
    let document = escape_terminal_bytes(editor.document().as_bytes());
    let prefix = escape_terminal_bytes(&editor.document().as_bytes()[..editor.cursor()]);
    let cursor_logical_line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let cursor_line_prefix = prefix.rsplit('\n').next().unwrap_or_default();
    let mut lines = Vec::new();
    let mut rows_before_cursor = 0_usize;

    for (line_index, line) in document.split('\n').enumerate() {
        let first_row = lines.len();
        wrap_editor_line(line, width, &mut lines);
        if line_index < cursor_logical_line {
            rows_before_cursor = rows_before_cursor.saturating_add(lines.len() - first_row);
        }
    }

    let (cursor_row_in_line, cursor_column) = wrapped_cursor(cursor_line_prefix, width);
    EditorLayout {
        lines,
        cursor_row: u16::try_from(rows_before_cursor.saturating_add(cursor_row_in_line))
            .unwrap_or(u16::MAX),
        cursor_column,
    }
}

fn wrap_editor_line(line: &str, width: u16, output: &mut Vec<Line<'static>>) {
    if width == 0 {
        return;
    }
    let output_start = output.len();
    let source = Line::from(line);
    let mut current = String::new();
    let mut current_width = 0_u16;
    for grapheme in source.styled_graphemes(Style::default()) {
        let grapheme_width = grapheme.symbol.cell_width();
        if grapheme_width > width {
            continue;
        }
        if current_width > 0 && current_width.saturating_add(grapheme_width) > width {
            output.push(Line::from(std::mem::take(&mut current)));
            current_width = 0;
        }
        current.push_str(grapheme.symbol);
        current_width = current_width.saturating_add(grapheme_width);
        if current_width == width {
            output.push(Line::from(std::mem::take(&mut current)));
            current_width = 0;
        }
    }
    if !current.is_empty() || output.len() == output_start {
        output.push(Line::from(current));
    }
}

fn wrapped_cursor(line_prefix: &str, width: u16) -> (usize, u16) {
    if width == 0 {
        return (0, 0);
    }
    let source = Line::from(line_prefix);
    let mut row = 0_usize;
    let mut column = 0_u16;
    for grapheme in source.styled_graphemes(Style::default()) {
        let grapheme_width = grapheme.symbol.cell_width();
        if grapheme_width > width {
            continue;
        }
        if column > 0 && column.saturating_add(grapheme_width) > width {
            row = row.saturating_add(1);
            column = 0;
        }
        column = column.saturating_add(grapheme_width);
        if column == width {
            row = row.saturating_add(1);
            column = 0;
        }
    }
    (row, column)
}

fn floating_area(area: Rect, width: u16, height: u16) -> Rect {
    let vertical = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Percentage(100_u16.saturating_sub(height) / 2),
            Constraint::Percentage(height),
            Constraint::Min(0),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage(100_u16.saturating_sub(width) / 2),
            Constraint::Percentage(width),
            Constraint::Min(0),
        ])
        .split(vertical[1]);
    horizontal[1]
}

fn side_lines(side: &SideSnapshot, kind: TrafficKind, mode: DisplayMode) -> Vec<Line<'static>> {
    match mode {
        DisplayMode::Pretty => pretty_lines(side),
        DisplayMode::Raw => raw_lines(side, kind),
        DisplayMode::Hex => hex_lines(side, kind),
    }
}

fn pretty_lines(side: &SideSnapshot) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(start_line) = &side.start_line {
        lines.push(Line::styled(
            start_line.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    for (name, value) in &side.headers {
        lines.push(Line::from(format!(
            "{name}: {}",
            escape_terminal_bytes(value)
        )));
    }
    if side.start_line.is_some() || !side.headers.is_empty() {
        lines.push(Line::from(""));
    }
    let body = pretty_body(&side.headers, &side.body);
    lines.extend(body.lines().map(|line| Line::from(line.to_owned())));
    append_body_status(&mut lines, side);
    if lines.is_empty() {
        lines.push(Line::from("No content observed"));
    }
    lines
}

fn raw_lines(side: &SideSnapshot, kind: TrafficKind) -> Vec<Line<'static>> {
    let (bytes, status) = display_bytes(side, kind);
    let mut lines = escape_terminal_bytes(bytes)
        .lines()
        .map(|line| Line::from(line.to_owned()))
        .collect::<Vec<_>>();
    if let Some(status) = status {
        lines.push(Line::styled(status, Style::default().fg(Color::Yellow)));
    }
    if lines.is_empty() {
        lines.push(Line::from("No bytes observed"));
    }
    lines
}

fn hex_lines(side: &SideSnapshot, kind: TrafficKind) -> Vec<Line<'static>> {
    let (bytes, status) = display_bytes(side, kind);
    let mut lines = bytes
        .chunks(16)
        .enumerate()
        .map(|(line, chunk)| {
            let offset = line.saturating_mul(16);
            Line::from(format!("{offset:08x}  {}", hex_ascii(chunk)))
        })
        .collect::<Vec<_>>();
    if let Some(status) = status {
        lines.push(Line::styled(status, Style::default().fg(Color::Yellow)));
    }
    if lines.is_empty() {
        lines.push(Line::from("No bytes observed"));
    }
    lines
}

fn display_bytes(side: &SideSnapshot, kind: TrafficKind) -> (&[u8], Option<String>) {
    if kind == TrafficKind::Tcp {
        let status = body_status(side);
        return (&side.body, status);
    }
    match &side.wire {
        WireState::Pending => (&[], Some("Raw capture pending".to_owned())),
        WireState::Captured {
            bytes,
            observed_bytes,
            truncated,
        } => {
            let status = truncated.then(|| {
                format!(
                    "[truncated: retained {} of {observed_bytes} bytes]",
                    bytes.len()
                )
            });
            (bytes, status)
        }
        WireState::Failed(reason) | WireState::Unavailable(reason) => {
            (&[], Some(format!("Raw unavailable: {reason}")))
        }
    }
}

fn append_body_status(lines: &mut Vec<Line<'static>>, side: &SideSnapshot) {
    if let Some(status) = body_status(side) {
        lines.push(Line::styled(status, Style::default().fg(Color::Yellow)));
    }
}

fn body_status(side: &SideSnapshot) -> Option<String> {
    if side.body_incomplete {
        return Some("[incomplete: one or more UI events were dropped]".to_owned());
    }
    side.body_truncated.then(|| {
        format!(
            "[truncated: retained {} of {} body bytes]",
            side.body.len(),
            side.observed_body_bytes
        )
    })
}

fn pretty_body(headers: &[(String, Vec<u8>)], body: &[u8]) -> String {
    if is_json(headers)
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(body)
        && let Ok(pretty) = serde_json::to_string_pretty(&value)
    {
        return pretty;
    }
    if std::str::from_utf8(body).is_ok() {
        return escape_terminal_bytes(body);
    }
    escape_terminal_bytes(body)
}

fn is_json(headers: &[(String, Vec<u8>)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && std::str::from_utf8(value).is_ok_and(|value| {
                let media_type = value.split(';').next().unwrap_or_default().trim();
                media_type.eq_ignore_ascii_case("application/json")
                    || media_type.to_ascii_lowercase().ends_with("+json")
            })
    })
}

fn render_diagnostics(frame: &mut Frame<'_>, model: &TuiModel) {
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Percentage(45),
            Constraint::Min(5),
            Constraint::Length(8),
        ])
        .split(frame.area());
    render_evidence(frame, model, areas[0]);
    render_operational_logs(frame, model, areas[1]);
    render_stats(frame, model, areas[2]);
}

fn render_operational_logs(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let lines = model
        .operational_logs
        .iter()
        .map(|message| Line::from(escape_terminal_bytes(message.as_bytes())))
        .collect::<Vec<_>>();
    let border_style = if model.focus == FocusPane::Logs {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Operational logs")
                    .border_style(border_style)
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false })
            .scroll((model.log_scroll, 0)),
        area,
    );
}

fn render_stats(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let closed = model.rows.iter().filter(|row| row.closed).count();
    let (client_bytes, upstream_bytes) = model.rows.iter().fold((0_u64, 0_u64), |total, row| {
        (
            total.0.saturating_add(row.client_to_upstream_bytes),
            total.1.saturating_add(row.upstream_to_client_bytes),
        )
    });
    let lines = vec![
        Line::from(format!("rows: {} (closed {closed})", model.rows.len())),
        Line::from(format!("bytes: {client_bytes} / {upstream_bytes}")),
        Line::from(format!(
            "UI dropped={} capture failures={} truncations={}",
            model.dropped_events, model.capture_failures, model.capture_truncations
        )),
        Line::from(format!(
            "paused={} interactive={}",
            model.paused_flows,
            escape_terminal_bytes(model.interactive_status.as_bytes())
        )),
        Line::from("1/2 page | Ctrl+j/k pane | j/k scroll | Enter expand | q back | Ctrl+c/Q quit"),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().title("Statistics").borders(Borders::ALL)),
        area,
    );
}

/// Escapes terminal control bytes while preserving ordinary UTF-8 text.
pub(super) fn escape_terminal_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        match std::str::from_utf8(&bytes[cursor..]) {
            Ok(text) => {
                push_escaped_text(&mut output, text);
                break;
            }
            Err(error) if error.valid_up_to() > 0 => {
                let valid_end = cursor.saturating_add(error.valid_up_to());
                if let Ok(text) = std::str::from_utf8(&bytes[cursor..valid_end]) {
                    push_escaped_text(&mut output, text);
                }
                cursor = valid_end;
            }
            Err(_) => {
                let byte = bytes[cursor];
                let _ = write!(output, "\\x{byte:02x}");
                cursor += 1;
            }
        }
    }
    output
}

fn push_escaped_text(output: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '\n' => output.push('\n'),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                for byte in character.to_string().as_bytes() {
                    let _ = write!(output, "\\x{byte:02x}");
                }
            }
            character => output.push(character),
        }
    }
}

pub(super) fn hex_ascii(bytes: &[u8]) -> String {
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let padding = " ".repeat(16_usize.saturating_sub(bytes.len()).saturating_mul(3));
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
    format!("{hex}{padding} |{ascii}|")
}
