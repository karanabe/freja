//! Pingora compatibility boundary.
//!
//! Protocol processing is deliberately outside this module. This adapter owns
//! only Pingora's connection callback and delegates the supplied transport to
//! a runtime-independent handler. The current CLI selects the Tokio fallback
//! because Pingora does not expose the listener metadata needed by Freja's
//! existing multi-listener bootstrap without additional service wiring.

use std::{future::Future, pin::Pin, sync::Arc};

use crate::{EngineKind, ListenerEngine};
use async_trait::async_trait;
use pingora_core::{apps::ServerApp, protocols::Stream, server::ShutdownWatch};

/// Pingora compatibility baseline required by Freja's runtime adapter.
pub const COMPATIBILITY_BASELINE: &str = "0.8.1";

/// Runtime identity for the Pingora `ServerApp` adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct PingoraEngine;

impl ListenerEngine for PingoraEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::PingoraServerApp
    }
}

/// Boxed transport-handler future used without exposing Pingora to policy,
/// inspection, audit, hook, or UI crates.
pub type PingoraHandlerFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Narrow data-plane callback invoked with one Pingora transport stream.
pub trait PingoraConnectionHandler: Send + Sync + 'static {
    fn serve<'a>(&'a self, stream: Stream, shutdown: &'a ShutdownWatch)
    -> PingoraHandlerFuture<'a>;
}

/// Concrete Pingora 0.8.1 [`ServerApp`] that consumes each stream exactly once.
///
/// Returning `None` is intentional: Hyper and CONNECT upgrades own connection
/// reuse, so a processed transport must not be returned to Pingora's reuse loop.
#[derive(Debug)]
pub struct PingoraServerApp<H> {
    handler: H,
}

impl<H> PingoraServerApp<H> {
    pub const fn new(handler: H) -> Self {
        Self { handler }
    }

    pub const fn handler(&self) -> &H {
        &self.handler
    }
}

#[async_trait]
impl<H> ServerApp for PingoraServerApp<H>
where
    H: PingoraConnectionHandler,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        self.handler.serve(stream, shutdown).await;
        None
    }
}

#[cfg(test)]
mod tests {
    use pingora_core::apps::ServerApp;

    use super::PingoraServerApp;

    fn assert_server_app<T: ServerApp>() {}

    #[test]
    fn adapter_has_the_pingora_server_app_contract() {
        struct Handler;

        impl super::PingoraConnectionHandler for Handler {
            fn serve<'a>(
                &'a self,
                _stream: pingora_core::protocols::Stream,
                _shutdown: &'a pingora_core::server::ShutdownWatch,
            ) -> super::PingoraHandlerFuture<'a> {
                Box::pin(async {})
            }
        }

        assert_server_app::<PingoraServerApp<Handler>>();
    }
}
