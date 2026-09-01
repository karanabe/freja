//! ratatui presentation driven exclusively by immutable [`crate::UiEvent`] snapshots.

use std::time::Duration;

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);

mod input;
mod model;
mod render;
mod runtime;
mod terminal;

pub use model::{FlowSnapshot, HttpSnapshot, PrefixSnapshot, TuiModel};
pub use render::render;
pub use runtime::{TuiTask, run_tui, spawn_tui};
pub use terminal::TuiError;

#[cfg(test)]
use render::hex_ascii;

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
