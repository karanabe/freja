use super::escape_terminal_bytes;
use crate::tui::{FocusPane, TraceSnapshot, TrafficKind, TrafficRow, TuiModel};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

pub(super) fn render_evidence(frame: &mut Frame<'_>, model: &TuiModel, area: Rect) {
    let row = model.evidence_row();
    let lines = evaluation_lines(model, row);
    let border_style = if model.focus == FocusPane::Evidence {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    };
    let block = Block::default()
        .title("Findings / DecisionTrace | j/k select | Enter rule | z expand")
        .border_style(border_style)
        .borders(Borders::ALL);
    let mut evidence_area = block.inner(area);
    frame.render_widget(block, area);
    if let Some(row) = row.filter(|row| row.kind == TrafficKind::Http) {
        let maximum_lines = if model.expanded_pane == Some(FocusPane::Evidence) {
            6
        } else {
            2
        };
        let context = request_context(row, evidence_area.width, maximum_lines);
        let height = u16::try_from(context.len())
            .unwrap_or(u16::MAX)
            .min(evidence_area.height.saturating_sub(1));
        let context_area = Rect {
            height,
            ..evidence_area
        };
        frame.render_widget(
            Paragraph::new(context).style(Style::default().fg(Color::Cyan)),
            context_area,
        );
        evidence_area.y = evidence_area.y.saturating_add(height);
        evidence_area.height = evidence_area.height.saturating_sub(height);
    }
    if model.evidence_missing() || row.is_none_or(|row| row.traces.is_empty()) {
        let message = if model.evidence_missing() {
            "Original evaluation no longer retained; no replacement selected. j/k selects explicitly."
        } else {
            "No evaluations retained. Findings do not identify an applied rule."
        };
        let notice = Rect {
            height: evidence_area.height.min(2),
            ..evidence_area
        };
        frame.render_widget(
            Paragraph::new(message)
                .wrap(Wrap { trim: false })
                .style(Style::default().fg(Color::Yellow)),
            notice,
        );
        evidence_area.y = evidence_area.y.saturating_add(notice.height);
        evidence_area.height = evidence_area.height.saturating_sub(notice.height);
    }
    let scroll = model
        .evidence_view
        .anchor
        .and_then(|id| {
            row.and_then(|row| {
                row.traces
                    .iter()
                    .position(|trace| trace.id == id)
                    .map(|index| index + row.findings.len())
            })
        })
        .map_or(model.diagnostics_scroll, |index| {
            let height = wrap_evidence_lines(lines[..index].to_vec(), evidence_area.width).len();
            u16::try_from(
                (i64::try_from(height).unwrap_or(i64::MAX) + i64::from(model.evidence_view.scroll))
                    .clamp(0, 65535),
            )
            .unwrap_or(u16::MAX)
        });
    frame.render_widget(
        Paragraph::new(wrap_evidence_lines(lines, evidence_area.width)).scroll((scroll, 0)),
        evidence_area,
    );
}

pub(super) fn render_rule_detail(frame: &mut Frame<'_>, model: &TuiModel) {
    let Some(detail) = &model.evidence_view.detail else {
        return;
    };
    let area = frame.area();
    frame.render_widget(Clear, area);
    let block = Block::default()
        .title("Rule detail (read-only) | Enter/q close | j/k/arrows/Pg scroll | Home top")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let snapshot = &detail.snapshot;
    let trace = &snapshot.trace;
    let identity = detail.identity.1.map_or_else(
        || format!("TCP Session: {}", detail.identity.0),
        |id| format!("Transaction: {id} | Session: {}", detail.identity.0),
    );
    let mut header = vec![
        Line::from(identity),
        Line::from(format!(
            "Evaluation #{} | generation={} | stage={:?}",
            snapshot.id, trace.policy_generation, trace.evaluated_stage
        )),
    ];
    header.extend(bounded_context_lines(
        &escape_terminal_bytes(detail.request.as_bytes()).replace('\n', "\\n"),
        inner.width,
        2,
    ));
    if detail.request_incomplete {
        header.push(Line::from("[Request context shortened by retention limit]"));
    }
    header.push(Line::styled(
        if model.detail_original_retained() {
            "Frozen evaluation view; forwarding and event delivery continue."
        } else {
            "Original evaluation evicted; this frozen detail remains. No replacement selected."
        },
        Style::default().fg(Color::Yellow),
    ));
    let header = wrap_evidence_lines(header, inner.width);
    let height = u16::try_from(header.len())
        .unwrap_or(u16::MAX)
        .min(inner.height);
    frame.render_widget(Paragraph::new(header), Rect { height, ..inner });
    let body = Rect {
        y: inner.y.saturating_add(height),
        height: inner.height.saturating_sub(height),
        ..inner
    };
    let lines = rule_detail_lines(snapshot);
    // Escape every dynamic value, including values carried in reasons and definitions.
    let lines: Vec<Line<'static>> = lines
        .into_iter()
        .flat_map(|line| {
            let escaped = escape_terminal_bytes(line.to_string().as_bytes());
            escaped
                .split('\n')
                .map(|line| Line::from(line.to_owned()))
                .collect::<Vec<_>>()
        })
        .collect();
    let lines = wrap_evidence_lines(lines, body.width);
    let maximum_scroll = lines.len().saturating_sub(usize::from(body.height));
    let paragraph = Paragraph::new(lines);
    frame.render_widget(
        paragraph.scroll((
            detail
                .scroll
                .min(u16::try_from(maximum_scroll).unwrap_or(u16::MAX)),
            0,
        )),
        body,
    );
}

/// Deterministic grapheme wrapping lets selection anchor to the same evaluation
/// at any terminal width, without relying on ratatui's experimental line count.
fn wrap_evidence_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let mut wrapped = Vec::new();
    for line in lines {
        let mut text = String::new();
        let mut used = 0;
        for grapheme in line.styled_graphemes(Style::default()) {
            let size = Line::from(grapheme.symbol).width();
            if used + size > usize::from(width) && !text.is_empty() {
                wrapped.push(Line::styled(std::mem::take(&mut text), line.style));
                used = 0;
            }
            text.push_str(grapheme.symbol);
            used += size;
        }
        wrapped.push(Line::styled(text, line.style));
    }
    wrapped
}

fn append_definition(
    lines: &mut Vec<Line<'static>>,
    field: &freja_policy::evidence::DefinitionText,
) {
    if field.incomplete() {
        lines.push(Line::styled("[INCOMPLETE: definition field exceeded 16 KiB or could not be serialized; suffix unavailable]", Style::default().fg(Color::Yellow)));
    }
    lines.extend(field.text().lines().map(|line| Line::from(line.to_owned())));
}

fn evaluation_target(target: Option<&freja_domain::EvaluationTarget>) -> String {
    use freja_domain::EvaluationTarget;

    let (requested, resolved) = match target {
        Some(EvaluationTarget::Requested(requested)) => (requested, None),
        Some(EvaluationTarget::Resolved(resolved)) => {
            (resolved.requested(), Some(resolved.resolved_ip()))
        }
        None => return "connection: unavailable".to_owned(),
    };
    let destination = freja_domain::UpstreamEndpoint::new(
        requested.requested_host().clone(),
        requested.destination_port(),
    );
    let resolved = resolved.map_or_else(
        || "unresolved".to_owned(),
        |ip| std::net::SocketAddr::new(ip, requested.destination_port().get()).to_string(),
    );
    format!(
        "{} -> {destination} / evaluated={resolved}",
        requested.source_ip()
    )
}

/// Uses only the selected transaction's retained snapshot, never session targets
/// or another row. Context stays visible while the existing evidence scrolls.
fn request_context(row: &TrafficRow, width: u16, maximum_lines: usize) -> Vec<Line<'static>> {
    let identity = row.transaction_id.map_or_else(
        || "Transaction: unavailable".to_owned(),
        |id| format!("Transaction: {id}"),
    );
    let mut lines = vec![Line::from(identity)];
    let Some(start_line) = row.request.start_line.as_deref() else {
        lines.push(Line::from("Request: unavailable (not retained)"));
        return lines;
    };
    // Origin-form and asterisk-form do not contain an authority. Label the
    // observed Host header explicitly rather than inventing an absolute URL.
    let host = if row.target.starts_with('/') || row.target == "*" {
        let value = row
            .request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"));
        value.map_or_else(
            || "Host header: unavailable | ".to_owned(),
            |(_, value)| format!("Host header: {} | ", escape_terminal_bytes(value)),
        )
    } else {
        String::new()
    };
    let summary = escape_terminal_bytes(format!("{host}Request: {start_line}").as_bytes())
        .replace('\n', "\\n");
    lines.extend(bounded_context_lines(&summary, width, maximum_lines));
    lines
}

/// Wraps display text at grapheme boundaries with an explicit omission marker.
/// The row owns the bounded source; these temporary lines add no retained state.
fn bounded_context_lines(text: &str, width: u16, maximum_lines: usize) -> Vec<Line<'static>> {
    const OMITTED: &str = "... [shortened]";
    let source = Line::from(text);
    let mut graphemes = source.styled_graphemes(Style::default()).peekable();
    let mut lines = Vec::new();
    let mut remaining_width = source.width();
    for index in 0..maximum_lines {
        let shortened = index + 1 == maximum_lines && remaining_width > usize::from(width);
        let available =
            usize::from(width).saturating_sub(if shortened { OMITTED.len() } else { 0 });
        let mut line = String::new();
        let mut used = 0;
        while let Some(grapheme) = graphemes.peek() {
            let length = Line::from(grapheme.symbol).width();
            if used + length > available {
                break;
            }
            used += length;
            line.push_str(grapheme.symbol);
            graphemes.next();
        }
        remaining_width = remaining_width.saturating_sub(used);
        if shortened {
            line.push_str(OMITTED);
        }
        lines.push(Line::from(line));
        if graphemes.peek().is_none() {
            break;
        }
    }
    lines
}

fn evaluation_lines(model: &TuiModel, row: Option<&TrafficRow>) -> Vec<Line<'static>> {
    row.map_or_else(Vec::new, |row| {
        let findings = row.findings.iter().map(|finding| {
            Line::styled(
                format!(
                    "finding {} {:?} {:?} {:?}",
                    finding.detector_id, finding.severity, finding.confidence, finding.direction
                ),
                Style::default().fg(Color::Yellow),
            )
        });
        let selected = model.selected_evaluation().map(|snapshot| snapshot.id);
        let traces = row.traces.iter().map(|snapshot| {
            let trace = &snapshot.trace;
            let text = format!(
                "{}decision {:?} rule={} generation={} | {}",
                if selected == Some(snapshot.id) {
                    "> "
                } else {
                    "  "
                },
                trace.final_action,
                trace
                    .matched_rule
                    .as_ref()
                    .map_or("<default>", |id| id.as_str()),
                trace.policy_generation,
                evaluation_target(snapshot.target.as_ref()),
            );
            Line::styled(
                escape_terminal_bytes(text.as_bytes()),
                if selected == Some(snapshot.id) {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )
        });
        findings.chain(traces).collect()
    })
}

fn rule_detail_lines(snapshot: &TraceSnapshot) -> Vec<Line<'static>> {
    let trace = &snapshot.trace;
    let mut lines = vec![Line::from(evaluation_target(snapshot.target.as_ref()))];
    if let Some(evidence) = &snapshot.evidence {
        lines.push(Line::from(format!(
            "Source: {:?} | Enforcement at decision: {:?}",
            evidence.source(),
            evidence.enforcement()
        )));
        if let Some(acl) = evidence.acl() {
            append_acl_summary(&mut lines, acl, trace.evaluated_stage);
        }
    } else {
        lines.push(Line::from("Source/definition/enforcement: unavailable (not retained with this evaluation). Current same-ID rules are not substituted."));
    }
    lines.push(Line::from(format!(
        "Rule ID: {}",
        trace
            .matched_rule
            .as_ref()
            .map_or("<default: no individual rule>", |id| id.as_str())
    )));
    if let Some(evidence) = &snapshot.evidence {
        if evidence.source() != freja_policy::evidence::RuleSource::AclDefault {
            lines.push(Line::from(
                "Conditions (selected definition; JSON representation):",
            ));
            append_definition(&mut lines, evidence.conditions());
            lines.push(Line::from("Configured action (selected definition):"));
            append_definition(&mut lines, evidence.action());
        }
        if let Some(acl) = evidence.acl() {
            // A single selected rule is already fully described above.
            if acl.rule_count() > 0 && (acl.rule_count() > 1 || acl.selected_ordinal().is_none()) {
                lines.push(Line::from(
                    "Configured ACL rules (declaration order; results from this evaluation):",
                ));
                if acl.rule_count() > freja_policy::evidence::MAXIMUM_ACL_EVIDENCE_RULES {
                    lines.push(Line::from(format!(
                        "[Only the first {} of {} rule definitions are included; summary counts cover all rules]",
                        freja_policy::evidence::MAXIMUM_ACL_EVIDENCE_RULES, acl.rule_count()
                    )));
                }
                append_definition(&mut lines, acl.declarations());
            }
            if acl.rule_count() > 0 {
                lines.push(Line::from("all=AND; any=OR; not requires available facts. Ports are inclusive; host suffix includes subdomains. Method/header names ignore case; paths and header values are case-sensitive."));
            }
        } else {
            lines.push(Line::from(match evidence.source() {
                freja_policy::evidence::RuleSource::Inspection => "The policy matches the finding detector ID. Other fields describe the detector and its emitted findings. Pattern bytes are decimal octets; directions bound detection.",
                freja_policy::evidence::RuleSource::DestinationGuard => "Built-in address protection is independent of ordered ACL rules; the condition names the protected class.",
                freja_policy::evidence::RuleSource::ConnectPorts => "Built-in listener CONNECT allowlist.",
                _ => "Default policy has no individual rule declaration.",
            }));
        }
    }
    lines.push(Line::from(format!(
        "Policy action category: {:?} (not proof of execution)",
        trace.final_action
    )));
    lines.push(Line::from(
        "Communication outcome: this evaluation does not establish delivery.",
    ));
    if let Some(evidence) = &snapshot.evidence {
        lines.push(Line::from(match evidence.enforcement() {
            freja_domain::EnforcementMode::Observe => {
                "Observe: records policy denials without enforcing them."
            }
            freja_domain::EnforcementMode::Enforce => {
                "Enforce: applies policy actions; streaming cannot retract bytes already forwarded."
            }
        }));
    }
    lines.push(Line::from("Recorded match reasons (observed facts):"));
    if trace.match_reasons.is_empty() {
        lines.push(Line::from("No match reasons retained."));
    }
    for reason in &trace.match_reasons {
        lines.push(Line::from(format!(
            "{}: {}",
            reason.criterion, reason.observed
        )));
    }
    if snapshot.reasons_incomplete {
        lines.push(Line::from(
            "[Recorded reasons shortened by UI retention limits]",
        ));
    }
    lines
}

fn append_acl_summary(
    lines: &mut Vec<Line<'static>>,
    acl: &freja_policy::evidence::AclEvidence,
    stage: freja_domain::PolicyStage,
) {
    lines.push(Line::from(format!(
        "Configured ACL: {} rules | first match wins | default action: {}",
        acl.rule_count(),
        acl.default_action().text()
    )));
    if acl.rule_count() == 0 {
        lines.push(Line::from(
            "Why default: no ACL rules were configured; there were no rule conditions to match.",
        ));
    } else {
        lines.push(Line::from(format!(
            "This evaluation: {} checked | {} did not match | {} unavailable at this stage | {} not evaluated",
            acl.evaluated(), acl.did_not_match(), acl.unavailable(), acl.rule_count() - acl.evaluated()
        )));
        lines.push(Line::from(acl.selected_ordinal().map_or_else(
            || "Why default: no configured rule matched at this stage.".to_owned(),
            |order| format!("Selected rule #{order}; evaluation stopped at the first match."),
        )));
    }
    let (inputs, unavailable) = match stage {
        freja_domain::PolicyStage::RequestedDestination => (
            "client IP, requested host/port, protocol",
            Some("resolved IP and HTTP method/path/headers"),
        ),
        freja_domain::PolicyStage::ResolvedDestination => (
            "client IP, requested host/port, protocol, resolved IP",
            Some("HTTP method/path/headers"),
        ),
        freja_domain::PolicyStage::HttpRequest => (
            "destination facts and this request's method, path, sanitized headers",
            None,
        ),
        freja_domain::PolicyStage::HttpResponse => (
            "destination facts and sanitized response headers",
            Some("request method/path"),
        ),
        freja_domain::PolicyStage::Streaming => ("unavailable for this stage", None),
    };
    lines.push(Line::from(format!("ACL inputs: {inputs}.")));
    if let Some(unavailable) = unavailable {
        lines.push(Line::from(format!(
            "Unavailable at this stage: {unavailable}."
        )));
    }
    lines.push(Line::from("This is the ACL configuration; destination guards and payload inspection are separate checks."));
}
