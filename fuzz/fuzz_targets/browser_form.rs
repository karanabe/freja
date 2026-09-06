#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    freja_http_test_server::fuzz_browser_form(data);
});
