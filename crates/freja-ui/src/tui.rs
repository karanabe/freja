//! ratatui presentation driven exclusively by immutable [`crate::UiEvent`] snapshots.

use std::time::Duration;

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

mod editor;
mod input;
mod model;
mod render;
mod runtime;
mod terminal;

pub use model::{
    DetailLayout, DisplayMode, FocusPane, SelectedSide, SideSnapshot, TrafficKind, TrafficRow,
    TuiModel, TuiPage, WireState,
};
pub use render::render;
pub use runtime::{TuiTask, run_tui, spawn_tui};
pub use terminal::TuiError;

#[cfg(test)]
use render::{escape_terminal_bytes, hex_ascii};

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::{DisplayMode, TuiModel, escape_terminal_bytes, hex_ascii, render};
    use crate::UiEvent;
    use freja_domain::{Direction, SessionId, TransactionId};
    use freja_policy::hook::{HttpRequestSnapshot, InterceptContext, InterceptRequest, WireBody};

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
        model.show_diagnostics();

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| render(frame, &model)).unwrap();

        assert_eq!(model.rows().len(), 1);
        assert!(model.rows()[0].closed);
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<Vec<_>>()
            .join("");
        assert!(rendered.contains("listener bound without terminal writes"));
        assert!(hex_ascii(b"A\0").starts_with("41 00"));
        assert_eq!(escape_terminal_bytes(b"A\x1b[2J"), "A\\x1b[2J");
    }

    #[test]
    fn traffic_page_renders_split_http_details_and_exact_raw_bytes() {
        let session_id = SessionId::new();
        let transaction_id = TransactionId::new();
        let mut model = TuiModel::new(4, 4);
        model.apply(UiEvent::FlowOpened {
            session_id,
            client: "127.0.0.1:40000".to_owned(),
            target: "http-forward".to_owned(),
        });
        model.apply(UiEvent::HttpObserved {
            session_id,
            transaction_id,
            method: "POST".to_owned(),
            target: "http://example.test/api".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![("content-type".to_owned(), b"application/json".to_vec())],
        });
        model.apply(UiEvent::HttpResponseObserved {
            session_id,
            transaction_id,
            status: 200,
            version: "HTTP/1.1".to_owned(),
            headers: vec![("content-length".to_owned(), b"2".to_vec())],
        });
        model.apply(UiEvent::WireCaptured {
            session_id,
            transaction_id,
            direction: Direction::HttpRequestBody,
            bytes: b"POST http://example.test/api HTTP/1.1\r\n\r\n{}".to_vec(),
            observed_bytes: 48,
            truncated: false,
        });

        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|frame| render(frame, &model)).unwrap();
        let pretty = rendered_text(&terminal);
        assert!(pretty.contains("Request [Pretty]"));
        assert!(pretty.contains("Response [Pretty]"));
        assert!(pretty.contains("POST http://example.test/api HTTP/1.1"));
        assert!(pretty.contains("HTTP/1.1 200 OK"));

        model.cycle_display_mode();
        assert_eq!(model.display_mode, DisplayMode::Raw);
        terminal.draw(|frame| render(frame, &model)).unwrap();
        assert!(rendered_text(&terminal).contains("POST http://example.test/api HTTP/1.1\\r"));

        model.cycle_layout();
        terminal.draw(|frame| render(frame, &model)).unwrap();
        let request_wide = rendered_text(&terminal);
        assert!(request_wide.contains("Request [Raw]"));
        assert!(!request_wide.contains("Response [Raw]"));

        model.cycle_layout();
        terminal.draw(|frame| render(frame, &model)).unwrap();
        let response_wide = rendered_text(&terminal);
        assert!(!response_wide.contains("Request [Raw]"));
        assert!(response_wide.contains("Response [Raw]"));
    }

    #[test]
    fn paused_request_snapshot_preempts_a_non_paused_row() {
        let session_id = SessionId::new();
        let old_transaction = TransactionId::new();
        let paused_transaction = TransactionId::new();
        let mut model = TuiModel::new(1, 4);
        model.apply(UiEvent::HttpObserved {
            session_id,
            transaction_id: old_transaction,
            method: "GET".to_owned(),
            target: "http://example.test/old".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
        });
        let (response, _receiver) = tokio::sync::oneshot::channel();
        let request = InterceptRequest {
            context: InterceptContext {
                session_id,
                transaction_id: paused_transaction,
            },
            request: HttpRequestSnapshot {
                method: http::Method::POST,
                uri: http::Uri::from_static("/paused"),
                version: http::Version::HTTP_11,
                headers: http::HeaderMap::new(),
                body: WireBody::new("complete"),
                maximum_head_bytes: 1_024,
                maximum_body_bytes: 1_024,
            },
            response,
        };

        model.apply_intercept_request(&request);

        assert_eq!(model.rows().len(), 1);
        assert_eq!(model.rows()[0].transaction_id, Some(paused_transaction));
        assert_eq!(model.rows()[0].request.body, b"complete");
        assert!(model.selected_is_paused());
    }

    fn rendered_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<Vec<_>>()
            .join("")
    }
}
