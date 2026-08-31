#![no_main]
#![forbid(unsafe_code)]

use freja_proxy::http::{is_valid_absolute_target, is_valid_connect_target};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data)
        && let Ok(uri) = input.parse::<http::Uri>()
    {
        let _absolute = is_valid_absolute_target(&uri);
        let _connect = is_valid_connect_target(&uri);
    }
});
