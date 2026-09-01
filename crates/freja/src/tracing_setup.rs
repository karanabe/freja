use std::{
    error::Error,
    io::Write,
    sync::{Arc, Mutex},
};

use freja::AppError;
use freja_ui::{UiEvent, UiPublisher};
use tracing_subscriber::{EnvFilter, fmt::MakeWriter};

use super::MAXIMUM_TUI_LOG_LINE_BYTES;

#[derive(Clone)]
pub(super) struct TuiTracingRouter {
    publisher: Arc<Mutex<Option<UiPublisher>>>,
}

impl TuiTracingRouter {
    pub(super) fn new(publisher: UiPublisher) -> Self {
        Self {
            publisher: Arc::new(Mutex::new(Some(publisher))),
        }
    }

    fn publish(&self, message: String) {
        let Ok(publisher) = self.publisher.lock() else {
            return;
        };
        let Some(publisher) = publisher.as_ref() else {
            return;
        };
        let _outcome = publisher.try_publish(UiEvent::OperationalLog { message });
    }

    pub(super) fn disconnect(&self) {
        if let Ok(mut publisher) = self.publisher.lock() {
            publisher.take();
        }
    }
}

impl<'writer> MakeWriter<'writer> for TuiTracingRouter {
    type Writer = TuiTracingWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        TuiTracingWriter {
            router: self.clone(),
            bytes: Vec::new(),
            truncated: false,
        }
    }
}

pub(super) struct TuiTracingWriter {
    router: TuiTracingRouter,
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
pub(super) struct TracingInitializationError {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl std::fmt::Display for TracingInitializationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("could not install the tracing subscriber")
    }
}

impl Error for TracingInitializationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl Write for TuiTracingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let available = MAXIMUM_TUI_LOG_LINE_BYTES.saturating_sub(self.bytes.len());
        let copied = available.min(bytes.len());
        self.bytes.extend_from_slice(&bytes[..copied]);
        self.truncated |= copied < bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for TuiTracingWriter {
    fn drop(&mut self) {
        let raw = String::from_utf8_lossy(&self.bytes);
        let mut message = raw
            .trim()
            .chars()
            .map(|character| match character {
                '\r' | '\n' => ' ',
                character => character,
            })
            .collect::<String>();
        if self.truncated {
            message.push('…');
        }
        if !message.is_empty() {
            self.router.publish(message);
        }
    }
}

fn tracing_filter() -> EnvFilter {
    match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::new("info"),
    }
}

pub(super) fn initialize_tui_tracing(
    publisher: UiPublisher,
) -> Result<TuiTracingRouter, TracingInitializationError> {
    let router = TuiTracingRouter::new(publisher);
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_filter())
        .with_writer(router.clone())
        .try_init()
        .map_err(|source| TracingInitializationError { source })?;
    Ok(router)
}

pub(super) fn initialize_tracing() -> Result<(), TracingInitializationError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_filter())
        .try_init()
        .map_err(|source| TracingInitializationError { source })?;
    Ok(())
}

pub(super) fn print_error(error: &AppError) {
    eprintln!("error: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}
