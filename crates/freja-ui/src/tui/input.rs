use std::collections::VecDeque;

use freja_domain::TransactionId;
use freja_policy::hook::{
    DecodedBody, HeadMutationPlan, HeaderMutation, InteractiveDecision, InterceptRequest,
};
use http::{HeaderName, HeaderValue};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use tokio::sync::mpsc;

use super::{EVENT_POLL_INTERVAL, FocusPane, TuiError, TuiModel};

pub(super) fn handle_input(
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
    let input = event::read().map_err(|source| TuiError::Io {
        operation: "input read",
        source,
    })?;
    let Event::Key(key) = input else {
        return Ok(false);
    };
    if key.kind != KeyEventKind::Press {
        return Ok(false);
    }
    if editor.is_some() {
        handle_editor_key(key.code, model, pending, editor);
        return Ok(false);
    }
    match key.code {
        KeyCode::Char('q') => Ok(true),
        KeyCode::Char('1') => {
            model.show_traffic();
            Ok(false)
        }
        KeyCode::Char('2') => {
            model.show_diagnostics();
            Ok(false)
        }
        KeyCode::Char('v') => {
            model.toggle_layout();
            Ok(false)
        }
        KeyCode::Char('m') => {
            model.cycle_display_mode();
            Ok(false)
        }
        KeyCode::Char('h') => {
            model.select_request_side();
            Ok(false)
        }
        KeyCode::Char('l') => {
            model.select_response_side();
            Ok(false)
        }
        KeyCode::Tab => {
            model.cycle_focus();
            Ok(false)
        }
        KeyCode::Up | KeyCode::Char('k') if model.focus == FocusPane::Flows => {
            model.select_previous();
            Ok(false)
        }
        KeyCode::Down | KeyCode::Char('j') if model.focus == FocusPane::Flows => {
            model.select_next();
            Ok(false)
        }
        KeyCode::Up | KeyCode::Char('k') => {
            model.scroll_up(1);
            Ok(false)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.scroll_down(1);
            Ok(false)
        }
        KeyCode::PageUp => {
            model.scroll_up(10);
            Ok(false)
        }
        KeyCode::PageDown => {
            model.scroll_down(10);
            Ok(false)
        }
        KeyCode::Char('c') => {
            respond_selected(model, pending, InteractiveDecision::Continue);
            Ok(false)
        }
        KeyCode::Char('r') => {
            respond_selected(model, pending, InteractiveDecision::Reject);
            Ok(false)
        }
        KeyCode::Char('x') => {
            respond_selected(model, pending, InteractiveDecision::CancelModification);
            Ok(false)
        }
        KeyCode::Char('e') if model.selected_is_paused() => {
            *editor = Some(Editor::Header(String::new()));
            Ok(false)
        }
        KeyCode::Char('b') if model.selected_is_paused() => {
            *editor = Some(Editor::Body(String::new()));
            Ok(false)
        }
        _ => Ok(false),
    }
}

pub(super) enum Editor {
    Header(String),
    Body(String),
}

const MAXIMUM_MANUAL_BODY_BYTES: usize = 4 * 1_024;
const MAXIMUM_HEADER_INPUT_BYTES: usize = 8 * 1_024;

fn handle_editor_key(
    key: KeyCode,
    model: &TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
    editor_slot: &mut Option<Editor>,
) {
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
                respond_selected(model, pending, decision);
                *editor_slot = None;
            }
        }
        KeyCode::Char(character) => {
            let Some(editor) = editor_slot.as_mut() else {
                return;
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
}

fn parse_header_decision(value: &str) -> Option<InteractiveDecision> {
    let (name, value) = value.split_once(':')?;
    let name = name.trim().parse::<HeaderName>().ok()?;
    let value = value.trim().parse::<HeaderValue>().ok()?;
    Some(InteractiveDecision::EditHeaders(HeadMutationPlan {
        headers: vec![HeaderMutation::Set { name, value }],
    }))
}

fn respond_selected(
    model: &TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
    decision: InteractiveDecision,
) {
    let Some(transaction_id) = model.selected_transaction_id() else {
        return;
    };
    let Some(index) = pending
        .iter()
        .position(|request| request.context.transaction_id == transaction_id)
    else {
        return;
    };
    if let Some(request) = pending.remove(index) {
        let _response_result = request.response.send(decision);
    }
}

pub(super) fn drain_intercepts(
    receiver: &mut Option<mpsc::Receiver<InterceptRequest>>,
    pending: &mut VecDeque<InterceptRequest>,
    model: &mut TuiModel,
) {
    let Some(active) = receiver.as_mut() else {
        return;
    };
    let mut disconnected = false;
    loop {
        match active.try_recv() {
            Ok(request) => {
                model.apply_intercept_request(&request);
                pending.push_back(request);
            }
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

pub(super) fn paused_transactions(pending: &VecDeque<InterceptRequest>) -> Vec<TransactionId> {
    pending
        .iter()
        .map(|request| request.context.transaction_id)
        .collect()
}

pub(super) fn editor_status(
    model: &TuiModel,
    pending: &VecDeque<InterceptRequest>,
    editor: Option<&Editor>,
) -> String {
    match editor {
        Some(Editor::Header(value)) => format!("header name:value > {value}"),
        Some(Editor::Body(value)) => format!("body ({}/4096) > {value}", value.len()),
        None => model.selected_transaction_id().map_or_else(
            || "idle".to_owned(),
            |transaction_id| {
                pending
                    .iter()
                    .find(|request| request.context.transaction_id == transaction_id)
                    .map_or_else(
                        || "idle".to_owned(),
                        |_| format!("HTTP request {transaction_id}"),
                    )
            },
        ),
    }
}
