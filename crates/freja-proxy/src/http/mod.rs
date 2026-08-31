mod body;
mod headers;
mod server;
mod service;
mod target;

pub use server::HttpForwardServer;

/// Exercises the production absolute-form target parser without exposing its
/// internal routing representation.
pub fn is_valid_absolute_target(uri: &http::Uri) -> bool {
    target::ForwardTarget::from_absolute(uri).is_ok()
}

/// Exercises the production CONNECT authority-form target parser.
pub fn is_valid_connect_target(uri: &http::Uri) -> bool {
    target::ForwardTarget::from_connect(uri).is_ok()
}

/// Exercises production framing validation for fuzzers and diagnostics.
pub fn is_valid_framing(headers: &http::HeaderMap, maximum: usize) -> bool {
    headers::validate(headers, maximum).is_ok()
}
