#![no_main]
#![forbid(unsafe_code)]

use freja_policy::hook::{
    BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, WireBody, apply_http_mutation,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let mut headers = http::HeaderMap::new();
    let mutations = match (
        http::HeaderName::from_bytes(&data[..split]),
        http::HeaderValue::from_bytes(&data[split..]),
    ) {
        (Ok(name), Ok(value)) => vec![HeaderMutation::Set { name, value }],
        _ => Vec::new(),
    };
    let head = HeadMutationPlan { headers: mutations };
    let body = WireBody::new(bytes::Bytes::copy_from_slice(data));
    let replacement = BodyMutationPlan::Replace(DecodedBody::new(bytes::Bytes::copy_from_slice(
        &data[split..],
    )));
    let _result = apply_http_mutation(&mut headers, &body, &head, &replacement, data.len());
});
