use std::collections::VecDeque;

use freja_domain::TransactionId;
use freja_policy::hook::{InteractiveDecision, InterceptRequest};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use super::{EVENT_POLL_INTERVAL, FocusPane, TuiError, TuiModel, editor::EditorMode};

pub(super) fn handle_input(
    model: &mut TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
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
    Ok(handle_key(key, model, pending))
}

pub(super) fn handle_key(
    key: KeyEvent,
    model: &mut TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }
    if is_exit_key(key) {
        return true;
    }
    if model.editor.is_some() {
        handle_editor_key(key, model, pending);
        return false;
    }
    model.clear_input_notice();
    if key.code == KeyCode::Char('q') && model.expanded_pane().is_some() {
        model.close_expanded_pane();
        return false;
    }
    if model.expanded_pane().is_some() {
        match key.code {
            KeyCode::Char('e') if model.selected_is_paused() => {
                open_request_editor(model, pending, false);
            }
            KeyCode::Char('i') if model.selected_is_paused() => {
                open_request_editor(model, pending, true);
            }
            _ => handle_expanded_key(key.code, model),
        }
        return false;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('j') => model.focus_next(),
            KeyCode::Char('k') => model.focus_previous(),
            _ => {}
        }
        return false;
    }
    match key.code {
        KeyCode::Char('1') => {
            model.show_traffic();
        }
        KeyCode::Char('2') => {
            model.show_diagnostics();
        }
        KeyCode::Char('v') => {
            model.cycle_layout();
        }
        KeyCode::Char('m') => {
            model.cycle_display_mode();
        }
        KeyCode::Char('h') => {
            model.select_request_side();
        }
        KeyCode::Char('l') => {
            model.select_response_side();
        }
        KeyCode::Tab => {
            model.cycle_focus();
        }
        KeyCode::Up | KeyCode::Char('k') if model.focus == FocusPane::Flows => {
            model.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') if model.focus == FocusPane::Flows => {
            model.select_next();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            model.scroll_up(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            model.scroll_down(1);
        }
        KeyCode::PageUp => {
            model.scroll_up(10);
        }
        KeyCode::PageDown => {
            model.scroll_down(10);
        }
        KeyCode::Char('c') => {
            respond_selected(model, pending, InteractiveDecision::Continue);
        }
        KeyCode::Char('r') => {
            respond_selected(model, pending, InteractiveDecision::Reject);
        }
        KeyCode::Char('x') => {
            respond_selected(model, pending, InteractiveDecision::CancelModification);
        }
        KeyCode::Char('e') if model.selected_is_paused() => {
            open_request_editor(model, pending, false);
        }
        KeyCode::Char('i') if model.selected_is_paused() => {
            open_request_editor(model, pending, true);
        }
        KeyCode::Enter => {
            model.expand_focused_pane();
        }
        _ => {}
    }
    false
}

fn handle_expanded_key(key: KeyCode, model: &mut TuiModel) {
    match key {
        KeyCode::Up | KeyCode::Char('k') if model.focus == FocusPane::Flows => {
            model.select_previous();
        }
        KeyCode::Down | KeyCode::Char('j') if model.focus == FocusPane::Flows => {
            model.select_next();
        }
        KeyCode::Up | KeyCode::Char('k') => model.scroll_up(1),
        KeyCode::Down | KeyCode::Char('j') => model.scroll_down(1),
        KeyCode::PageUp => model.scroll_up(10),
        KeyCode::PageDown => model.scroll_down(10),
        KeyCode::Char('h') => model.select_request_side(),
        KeyCode::Char('l') => model.select_response_side(),
        KeyCode::Char('m') => model.cycle_display_mode(),
        _ => {}
    }
}

fn is_exit_key(key: KeyEvent) -> bool {
    key.code == KeyCode::Char('Q')
        || (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))
}

fn handle_editor_key(
    key: KeyEvent,
    model: &mut TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
) {
    if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL) {
        submit_editor(model, pending);
        return;
    }
    let Some(mode) = model
        .editor
        .as_ref()
        .map(super::editor::RequestEditor::mode)
    else {
        return;
    };
    match mode {
        EditorMode::Normal => handle_editor_normal_key(key, model, pending),
        EditorMode::Insert => handle_editor_insert_key(key, model),
    }
}

fn handle_editor_normal_key(
    key: KeyEvent,
    model: &mut TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
) {
    match key.code {
        KeyCode::Char('q') => model.editor = None,
        KeyCode::Char('s') => submit_editor(model, pending),
        KeyCode::Char('i') => {
            if let Some(editor) = model.editor.as_mut() {
                editor.enter_insert_mode();
            }
        }
        KeyCode::Char('h') | KeyCode::Left => {
            with_editor(model, super::editor::RequestEditor::move_left);
        }
        KeyCode::Char('j') | KeyCode::Down => {
            with_editor(model, super::editor::RequestEditor::move_down);
        }
        KeyCode::Char('k') | KeyCode::Up => {
            with_editor(model, super::editor::RequestEditor::move_up);
        }
        KeyCode::Char('l') | KeyCode::Right => {
            with_editor(model, super::editor::RequestEditor::move_right);
        }
        KeyCode::Char('0') | KeyCode::Home => {
            with_editor(model, super::editor::RequestEditor::move_home);
        }
        KeyCode::Char('$') | KeyCode::End => {
            with_editor(model, super::editor::RequestEditor::move_end);
        }
        _ => {}
    }
}

fn handle_editor_insert_key(key: KeyEvent, model: &mut TuiModel) {
    let Some(editor) = model.editor.as_mut() else {
        return;
    };
    match key.code {
        KeyCode::Esc => editor.enter_normal_mode(),
        KeyCode::Enter => editor.insert_newline(),
        KeyCode::Tab => editor.insert_tab(),
        KeyCode::Backspace => editor.backspace(),
        KeyCode::Delete => editor.delete(),
        KeyCode::Left => editor.move_left(),
        KeyCode::Right => editor.move_right(),
        KeyCode::Up => editor.move_up(),
        KeyCode::Down => editor.move_down(),
        KeyCode::Home => editor.move_home(),
        KeyCode::End => editor.move_end(),
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            editor.insert_character(character);
        }
        _ => {}
    }
}

fn with_editor(model: &mut TuiModel, action: impl FnOnce(&mut super::editor::RequestEditor)) {
    if let Some(editor) = model.editor.as_mut() {
        action(editor);
    }
}

fn open_request_editor(
    model: &mut TuiModel,
    pending: &VecDeque<InterceptRequest>,
    insert_mode: bool,
) {
    let Some(transaction_id) = model.selected_transaction_id() else {
        return;
    };
    let Some(request) = pending
        .iter()
        .find(|request| request.context.transaction_id == transaction_id)
    else {
        return;
    };
    match model.open_request_editor(request) {
        Ok(()) if insert_mode => {
            if let Some(editor) = model.editor.as_mut() {
                editor.enter_insert_mode();
            }
        }
        Ok(()) => {}
        Err(error) => model.set_input_notice(format!("request editor unavailable: {error}")),
    }
}

fn submit_editor(model: &mut TuiModel, pending: &mut VecDeque<InterceptRequest>) {
    let submission = match model
        .editor
        .as_ref()
        .map(super::editor::RequestEditor::submission)
    {
        Some(Ok(submission)) => submission,
        Some(Err(error)) => {
            if let Some(editor) = model.editor.as_mut() {
                editor.set_error(&error);
            }
            return;
        }
        None => return,
    };
    if respond_selected(model, pending, submission.decision) {
        model.apply_edited_request(submission.headers, submission.body);
    }
    model.editor = None;
}

fn respond_selected(
    model: &TuiModel,
    pending: &mut VecDeque<InterceptRequest>,
    decision: InteractiveDecision,
) -> bool {
    let Some(transaction_id) = model.selected_transaction_id() else {
        return false;
    };
    let Some(index) = pending
        .iter()
        .position(|request| request.context.transaction_id == transaction_id)
    else {
        return false;
    };
    if let Some(request) = pending.remove(index) {
        return request.response.send(decision).is_ok();
    }
    false
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

pub(super) fn editor_status(model: &TuiModel, pending: &VecDeque<InterceptRequest>) -> String {
    if let Some(editor) = model.editor.as_ref() {
        return editor.status().to_owned();
    }
    if let Some(notice) = model.input_notice.as_ref() {
        return notice.clone();
    }
    model.selected_transaction_id().map_or_else(
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
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use freja_domain::{SessionId, TransactionId};
    use freja_policy::hook::{
        HttpRequestSnapshot, InteractiveDecision, InterceptContext, InterceptRequest, WireBody,
    };
    use http::{HeaderMap, Method, Uri, Version};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use tokio::sync::oneshot;

    use super::handle_key;
    use crate::tui::{DetailLayout, FocusPane, TuiModel};

    #[test]
    fn navigation_expansion_and_exit_keys_do_not_conflict() {
        let mut model = TuiModel::default();
        let mut pending = VecDeque::new();

        assert!(!handle_key(
            key(KeyCode::Char('j'), KeyModifiers::CONTROL),
            &mut model,
            &mut pending,
        ));
        assert_eq!(model.focus, FocusPane::Detail);

        assert!(!handle_key(
            key(KeyCode::Enter, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert_eq!(model.expanded_pane(), Some(FocusPane::Detail));

        assert!(!handle_key(
            key(KeyCode::Char('j'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert_eq!(model.detail_scroll, 1);

        assert!(!handle_key(
            key(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert_eq!(model.expanded_pane(), None);
        assert!(!handle_key(
            key(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert!(handle_key(
            key(KeyCode::Char('Q'), KeyModifiers::SHIFT),
            &mut model,
            &mut pending,
        ));
        assert!(handle_key(
            key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &mut model,
            &mut pending,
        ));
    }

    #[test]
    fn layout_cycles_split_request_and_response() {
        let mut model = TuiModel::default();
        let mut pending = VecDeque::new();

        for expected in [
            DetailLayout::Request,
            DetailLayout::Response,
            DetailLayout::Split,
        ] {
            assert!(!handle_key(
                key(KeyCode::Char('v'), KeyModifiers::NONE),
                &mut model,
                &mut pending,
            ));
            assert_eq!(model.layout, expected);
        }
    }

    #[test]
    fn insert_mode_keeps_enter_for_newlines_and_normal_mode_submits() {
        let (mut model, mut pending, mut response) = paused_request();
        assert!(!handle_key(
            key(KeyCode::Char('i'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        let lines_before = model
            .editor
            .as_ref()
            .unwrap()
            .display_text()
            .matches('\n')
            .count();
        assert!(!handle_key(
            key(KeyCode::Enter, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert_eq!(
            model
                .editor
                .as_ref()
                .unwrap()
                .display_text()
                .matches('\n')
                .count(),
            lines_before + 1
        );

        assert!(!handle_key(
            key(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert!(model.editor.is_some());
        assert!(!handle_key(
            key(KeyCode::Esc, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert!(!handle_key(
            key(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        ));
        assert!(model.editor.is_none());
        assert!(response.try_recv().is_err());
    }

    #[test]
    fn unchanged_editor_document_resumes_with_continue() {
        let (mut model, mut pending, mut response) = paused_request();
        handle_key(
            key(KeyCode::Char('e'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
        handle_key(
            key(KeyCode::Char('s'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );

        assert!(model.editor.is_none());
        assert!(pending.is_empty());
        assert_eq!(response.try_recv().unwrap(), InteractiveDecision::Continue);
    }

    fn paused_request() -> (
        TuiModel,
        VecDeque<InterceptRequest>,
        oneshot::Receiver<InteractiveDecision>,
    ) {
        let (sender, receiver) = oneshot::channel();
        let request = InterceptRequest {
            context: InterceptContext {
                session_id: SessionId::new(),
                transaction_id: TransactionId::new(),
            },
            request: HttpRequestSnapshot {
                method: Method::POST,
                uri: Uri::from_static("/submit"),
                version: Version::HTTP_11,
                headers: HeaderMap::new(),
                body: WireBody::new("old"),
                maximum_head_bytes: 4 * 1_024,
                maximum_body_bytes: 4 * 1_024,
            },
            response: sender,
        };
        let mut model = TuiModel::default();
        model.apply_intercept_request(&request);
        let mut pending = VecDeque::new();
        pending.push_back(request);
        (model, pending, receiver)
    }

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }
}
