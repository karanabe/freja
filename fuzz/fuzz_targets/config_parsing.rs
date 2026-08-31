#![no_main]
#![forbid(unsafe_code)]

use freja_config::RawConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _result = RawConfig::parse(input).and_then(RawConfig::validate);
    }
});
