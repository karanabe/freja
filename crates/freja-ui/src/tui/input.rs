use std::collections::VecDeque;

use freja_policy::hook::{
    DecodedBody, HeadMutationPlan, HeaderMutation, InteractiveDecision, InterceptRequest,
};
use http::{HeaderName, HeaderValue};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use tokio::sync::mpsc;

use super::{EVENT_POLL_INTERVAL, TuiError, TuiModel};

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

pub(super) enum Editor {
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

pub(super) fn drain_intercepts(
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

pub(super) fn editor_status(
    pending: &VecDeque<InterceptRequest>,
    editor: Option<&Editor>,
) -> String {
    match editor {
        Some(Editor::Header(value)) => format!("header name:value > {value}"),
        Some(Editor::Body(value)) => format!("body ({}/4096) > {value}", value.len()),
        None => pending.front().map_or_else(
            || "idle".to_owned(),
            |request| format!("{:?} {}", request.stage, request.context.session_id),
        ),
    }
}
