use std::{collections::VecDeque, thread};

use freja_policy::hook::{InterceptRequest, RepeatRequest, RepeatResult};
use tokio::sync::{mpsc, oneshot};

use crate::{UiEvent, UiMetrics};

use super::{TuiError, TuiModel};
use super::{
    input::{
        drain_intercepts, drain_repeat_results, editor_status, handle_input, paused_transactions,
    },
    terminal::TerminalGuard,
};

/// Spawns the terminal owner on a dedicated OS thread.
///
/// # Errors
///
/// Returns [`TuiError::ThreadSpawn`] when the operating system cannot create
/// the dedicated terminal thread.
pub fn spawn_tui(
    receiver: mpsc::Receiver<UiEvent>,
    metrics: UiMetrics,
    intercept_receiver: Option<mpsc::Receiver<InterceptRequest>>,
    repeat_sender: Option<mpsc::Sender<RepeatRequest>>,
    repeat_receiver: Option<mpsc::Receiver<RepeatResult>>,
    retained_rows: usize,
) -> Result<TuiTask, TuiError> {
    let (exit_sender, exit_receiver) = oneshot::channel();
    let thread = thread::Builder::new()
        .name("freja-tui".to_owned())
        .spawn(move || {
            let result = run_tui(
                receiver,
                &metrics,
                intercept_receiver,
                repeat_sender.as_ref(),
                repeat_receiver,
                retained_rows,
            );
            let _send_result = exit_sender.send(());
            result
        })
        .map_err(TuiError::ThreadSpawn)?;
    Ok(TuiTask {
        exit_receiver,
        thread,
    })
}

/// Join and exit handles for the dedicated terminal owner.
pub struct TuiTask {
    exit_receiver: oneshot::Receiver<()>,
    thread: thread::JoinHandle<Result<(), TuiError>>,
}

impl TuiTask {
    /// Splits the task into an async exit notification and an OS-thread handle.
    pub fn into_parts(
        self,
    ) -> (
        oneshot::Receiver<()>,
        thread::JoinHandle<Result<(), TuiError>>,
    ) {
        (self.exit_receiver, self.thread)
    }
}

/// Runs the terminal event loop until Ctrl+C, `Q`, or producer shutdown.
///
/// # Errors
///
/// Returns [`TuiError::Io`] when terminal setup, drawing, or input polling fails.
pub fn run_tui(
    mut receiver: mpsc::Receiver<UiEvent>,
    metrics: &UiMetrics,
    mut intercept_receiver: Option<mpsc::Receiver<InterceptRequest>>,
    repeat_sender: Option<&mpsc::Sender<RepeatRequest>>,
    mut repeat_receiver: Option<mpsc::Receiver<RepeatResult>>,
    retained_rows: usize,
) -> Result<(), TuiError> {
    let mut terminal = TerminalGuard::enter()?;
    let mut model = TuiModel::new(retained_rows, 256);
    let mut pending = VecDeque::new();
    loop {
        let mut disconnected = false;
        loop {
            match receiver.try_recv() {
                Ok(event) => model.apply(event),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        drain_intercepts(&mut intercept_receiver, &mut pending, &mut model);
        drain_repeat_results(&mut repeat_receiver, &mut model);
        model.set_dropped_events(metrics.dropped_events());
        model.set_interactive_state(
            paused_transactions(&pending),
            editor_status(&model, &pending),
        );
        terminal.draw(&model)?;
        if disconnected || handle_input(&mut model, &mut pending, repeat_sender)? {
            return Ok(());
        }
    }
}
