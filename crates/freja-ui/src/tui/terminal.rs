use std::{error::Error, fmt, io};

use ratatui::DefaultTerminal;

use super::{TuiModel, render};

/// Terminal setup, rendering, or input failure.
#[derive(Debug)]
pub enum TuiError {
    /// Terminal initialization, rendering, or input I/O failed.
    Io {
        /// Stable terminal lifecycle operation.
        operation: &'static str,
        /// Underlying terminal I/O error.
        source: io::Error,
    },
    /// The dedicated terminal-owner thread could not be created.
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
pub(super) struct TerminalGuard {
    terminal: DefaultTerminal,
}

impl TerminalGuard {
    pub(super) fn enter() -> Result<Self, TuiError> {
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

    pub(super) fn draw(&mut self, model: &TuiModel) -> Result<(), TuiError> {
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
