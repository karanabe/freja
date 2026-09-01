#![no_main]
#![forbid(unsafe_code)]

use freja_proxy::http::{is_valid_framing, is_valid_wire_capture};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let mut headers = http::HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_bytes(&data[..split]) {
        headers.append(http::header::CONTENT_LENGTH, value);
    }
    if let Ok(value) = http::HeaderValue::from_bytes(&data[split..]) {
        headers.append(http::header::TRANSFER_ENCODING, value);
    }
    let _valid = is_valid_framing(&headers, 64 * 1_024);
    let _wire_valid = is_valid_wire_capture(data);
});
