use std::future;

use tokio::sync::watch;

/// Cloneable trigger for graceful listener and session shutdown.
#[derive(Debug, Clone)]
pub struct ShutdownSender {
    sender: watch::Sender<bool>,
}

impl ShutdownSender {
    /// Requests shutdown. Calling this more than once is harmless.
    pub fn shutdown(&self) {
        let _receiver_count = self.sender.send(true);
    }
}

/// Per-task observation side of the graceful shutdown signal.
#[derive(Debug, Clone)]
pub struct ShutdownSignal {
    receiver: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Reports whether shutdown has already been requested.
    pub fn is_cancelled(&self) -> bool {
        *self.receiver.borrow()
    }

    /// Waits until shutdown is requested. Dropping all senders does not imply shutdown.
    pub async fn cancelled(&mut self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            if self.receiver.changed().await.is_err() {
                future::pending::<()>().await;
            }
        }
    }
}

/// Creates a bounded latest-state shutdown channel.
pub fn shutdown_channel() -> (ShutdownSender, ShutdownSignal) {
    let (sender, receiver) = watch::channel(false);
    (ShutdownSender { sender }, ShutdownSignal { receiver })
}
