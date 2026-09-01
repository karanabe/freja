use ratatui::{
    Frame,
    layout::{Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
};

use super::TuiModel;

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
pub(super) fn hex_ascii(bytes: &[u8]) -> String {
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
