mod body;
mod headers;
mod server;
mod service;
mod target;
mod wire;

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

/// Exercises the bounded capture-only HTTP/1 framing state machine.
pub fn is_valid_wire_capture(input: &[u8]) -> bool {
    wire::is_valid_capture_framing(input)
}
