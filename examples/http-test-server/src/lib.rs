#![forbid(unsafe_code)]
//! Local HTTP origin used to exercise Freja without a public network service.
//!
//! The server exposes method-echo, status, redirect, delay, bounded streaming,
//! fixed-size response endpoints, and a bounded browser form lab. [`app`] returns the Axum router so the
//! externally visible HTTP behavior can also be integration tested.

mod lab;
mod request_log;
mod routes;

use axum::{Router, middleware};

/// Maximum request body size accepted by an echo endpoint (one MiB).
pub const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// Builds the complete test-server router.
pub fn app() -> Router {
    routes::router().layer(middleware::from_fn(request_log::log_request))
}

/// Exercises the lab's bounded application form decoder for fuzz testing.
///
/// This does not parse HTTP framing or send requests. Inputs exceeding the
/// route's encoded-input limit are discarded before decoding.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_browser_form(bytes: &[u8]) {
    lab::fuzz_form(bytes);
}
