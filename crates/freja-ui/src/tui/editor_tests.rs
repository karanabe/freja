//! Request-editor caret and viewport regressions on ratatui's test backend.

use std::collections::VecDeque;

use freja_domain::{SessionId, TransactionId};
use freja_policy::hook::{HttpRequestSnapshot, InterceptContext, InterceptRequest, WireBody};
use http::{HeaderMap, Method, Uri, Version};
use ratatui::{
    Terminal,
    backend::{Backend, TestBackend},
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    layout::Position,
};

use super::{
    TuiModel,
    input::{handle_key, handle_key_with_repeat},
    render,
};

#[test]
fn repeat_caret_does_not_replace_or_reflow_unedited_characters() {
    let body = format!(
        "界e\u{301}\u{1b}[2J-BEGIN-{}-END\nSECOND-ROW",
        "0123456789".repeat(9)
    );

    for (width, height) in [(80, 24), (120, 30)] {
        let mut model = repeat_editor_model(&body);
        let before = screen(&model, width, height);
        let selected = model.repeat_selected;
        let editor_target = model.editor_target;
        let saved_body = model.repeat_workspaces[selected]
            .request
            .body
            .bytes()
            .to_vec();
        let mut pending = VecDeque::new();

        assert!(before.cursor_visible);
        let expected_cursor_x = [
            before.cursor.x.saturating_add(2),
            before.cursor.x.saturating_add(3),
            before.cursor.x.saturating_add(3),
            before.cursor.x.saturating_add(7),
        ];
        for (code, cursor_x) in [KeyCode::Right; 4].into_iter().zip(expected_cursor_x) {
            handle_key(key(code, KeyModifiers::NONE), &mut model, &mut pending);
            let moved = screen(&model, width, height);
            assert_eq!(moved.text, before.text);
            assert!(moved.cursor_visible);
            assert_eq!(moved.cursor.x, cursor_x);
        }

        for code in [KeyCode::Left, KeyCode::Down, KeyCode::Up] {
            handle_key(key(code, KeyModifiers::NONE), &mut model, &mut pending);
            assert_eq!(screen(&model, width, height).text, before.text);
        }

        handle_key(
            key(KeyCode::Char('i'), KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
        let insert_mode = screen(&model, width, height);
        for code in [KeyCode::Left, KeyCode::Right, KeyCode::Down, KeyCode::Up] {
            handle_key(key(code, KeyModifiers::NONE), &mut model, &mut pending);
            assert_eq!(screen(&model, width, height).text, insert_mode.text);
        }

        assert!(before.text.contains("\\x1b[2J-BEGIN"));
        assert!(!before.text.contains('\u{1b}'));
        assert_eq!(model.repeat_selected, selected);
        assert_eq!(model.editor_target, editor_target);
        assert_eq!(
            model.repeat_workspaces[selected]
                .request
                .body
                .bytes()
                .as_ref(),
            saved_body.as_slice()
        );
        assert_eq!(
            model
                .editor
                .as_ref()
                .and_then(|editor| editor.submission().ok())
                .map(|submission| submission.body),
            Some(body.as_bytes().to_vec())
        );
    }
}

#[test]
fn repeat_up_within_scrolled_viewport_does_not_move_the_rows() {
    let body = (0..30)
        .map(|line| format!("stable-line-{line:02}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut model = repeat_editor_model(&body);
    let initial = screen(&model, 80, 24);
    let initial_cursor = initial.cursor;
    let mut pending = VecDeque::new();

    for _ in 0..14 {
        handle_key(
            key(KeyCode::Down, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
        assert_eq!(screen(&model, 80, 24).text, initial.text);
    }
    handle_key(
        key(KeyCode::Down, KeyModifiers::NONE),
        &mut model,
        &mut pending,
    );
    let at_lower_edge = screen(&model, 80, 24);
    assert_ne!(at_lower_edge.text, initial.text);
    assert!(at_lower_edge.cursor_visible);

    handle_key(
        key(KeyCode::Up, KeyModifiers::NONE),
        &mut model,
        &mut pending,
    );
    let within_viewport = screen(&model, 80, 24);
    assert_eq!(within_viewport.text, at_lower_edge.text);
    assert_eq!(
        within_viewport.cursor.y.saturating_add(1),
        at_lower_edge.cursor.y
    );

    for _ in 0..16 {
        handle_key(
            key(KeyCode::Up, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
    }
    let returned = screen(&model, 80, 24);
    assert_eq!(returned.text, initial.text);
    for _ in 0..2 {
        handle_key(
            key(KeyCode::Down, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
    }
    let original_caret = screen(&model, 80, 24);
    assert_eq!(original_caret.text, initial.text);
    assert_eq!(original_caret.cursor, initial_cursor);
}

#[test]
fn repeat_caret_crosses_a_narrow_unicode_wrap_without_reflowing_text() {
    let body = format!("{}界-WRAP-END", "a".repeat(73));
    let mut model = repeat_editor_model(&body);
    let initial = screen(&model, 80, 24);
    let mut pending = VecDeque::new();

    for _ in 0..73 {
        handle_key(
            key(KeyCode::Right, KeyModifiers::NONE),
            &mut model,
            &mut pending,
        );
    }
    let before_wide_character = screen(&model, 80, 24);
    assert_eq!(before_wide_character.text, initial.text);
    assert_eq!(
        before_wide_character.cursor.x,
        initial.cursor.x.saturating_add(73)
    );

    handle_key(
        key(KeyCode::Right, KeyModifiers::NONE),
        &mut model,
        &mut pending,
    );
    let after_wide_character = screen(&model, 80, 24);
    assert_eq!(after_wide_character.text, initial.text);
    assert_eq!(
        after_wide_character.cursor.y,
        before_wide_character.cursor.y.saturating_add(1)
    );
    assert_eq!(
        after_wide_character.cursor.x,
        initial.cursor.x.saturating_add(2)
    );

    handle_key(
        key(KeyCode::Left, KeyModifiers::NONE),
        &mut model,
        &mut pending,
    );
    let returned = screen(&model, 80, 24);
    assert_eq!(returned.text, initial.text);
    assert_eq!(returned.cursor, before_wide_character.cursor);
}

#[test]
fn ordinary_interactive_editor_uses_the_stable_caret_layout() {
    let request = intercepted_request("interactive-界\nsecond-row");
    let mut model = TuiModel::new(2, 4);
    model.apply_intercept_request(&request);
    model.open_request_editor(&request).unwrap();
    let before = screen(&model, 80, 24);
    let mut pending = VecDeque::new();

    handle_key(
        key(KeyCode::Right, KeyModifiers::NONE),
        &mut model,
        &mut pending,
    );

    let after = screen(&model, 80, 24);
    assert_eq!(after.text, before.text);
    assert_ne!(after.cursor, before.cursor);
}

#[test]
fn repeat_send_changes_only_intentionally_edited_content() {
    let body = "first\nsecond-界";
    let mut pending = VecDeque::new();
    let (sender, mut receiver) = tokio::sync::mpsc::channel(2);
    let mut unchanged = repeat_editor_model(body);

    for code in [KeyCode::Right, KeyCode::Down, KeyCode::Up] {
        handle_key_with_repeat(
            key(code, KeyModifiers::NONE),
            &mut unchanged,
            &mut pending,
            Some(&sender),
        );
    }
    handle_key_with_repeat(
        key(KeyCode::Char('s'), KeyModifiers::NONE),
        &mut unchanged,
        &mut pending,
        Some(&sender),
    );
    let unchanged_request = receiver.try_recv().unwrap();
    assert_eq!(unchanged_request.request.body.bytes(), body.as_bytes());

    let mut edited = repeat_editor_model(body);
    for (code, modifiers) in [
        (KeyCode::Char('i'), KeyModifiers::NONE),
        (KeyCode::Char('X'), KeyModifiers::NONE),
        (KeyCode::Char('s'), KeyModifiers::CONTROL),
    ] {
        handle_key_with_repeat(
            key(code, modifiers),
            &mut edited,
            &mut pending,
            Some(&sender),
        );
    }
    let edited_request = receiver.try_recv().unwrap();
    assert_eq!(
        edited_request.request.body.bytes().as_ref(),
        "Xfirst\nsecond-界".as_bytes()
    );
}

fn repeat_editor_model(body: &str) -> TuiModel {
    let request = intercepted_request(body);
    let mut model = TuiModel::new(2, 4);
    assert!(model.create_repeat_workspace(&request));
    model.open_repeat_editor().unwrap();
    model
}

fn intercepted_request(body: &str) -> InterceptRequest {
    let (response, _receiver) = tokio::sync::oneshot::channel();
    InterceptRequest {
        context: InterceptContext {
            session_id: SessionId::new(),
            transaction_id: TransactionId::new(),
            source_ip: "127.0.0.1".parse().unwrap(),
        },
        request: HttpRequestSnapshot {
            method: Method::POST,
            uri: Uri::from_static("http://example.test/repeat"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: WireBody::new(body.as_bytes().to_vec()),
            maximum_head_bytes: 4 * 1_024,
            maximum_body_bytes: 4 * 1_024,
        },
        response,
    }
}

struct RenderedEditor {
    text: String,
    cursor: Position,
    cursor_visible: bool,
}

fn screen(model: &TuiModel, width: u16, height: u16) -> RenderedEditor {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|frame| render(frame, model)).unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect::<Vec<_>>()
        .join("");
    let cursor_visible = terminal.backend().cursor_visible();
    let cursor = terminal.backend_mut().get_cursor_position().unwrap();
    RenderedEditor {
        text,
        cursor,
        cursor_visible,
    }
}

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}
