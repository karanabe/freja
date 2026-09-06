//! Strict, small form interpretation for two known synthetic fields. This is
//! application data decoding, independent from HTTP framing and proxy parsing.

use percent_encoding::percent_decode_str;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub(super) struct Fields {
    case: String,
    message: String,
}

pub(super) fn parse(bytes: &[u8]) -> Result<Fields, &'static str> {
    let encoded = std::str::from_utf8(bytes).map_err(|_| "Form bytes must be UTF-8.")?;
    let mut case = None;
    let mut message = None;
    for (index, pair) in encoded.split('&').enumerate() {
        if index >= 2 {
            return Err(
                "Exactly two fields are allowed: case and message; no duplicates or extra fields.",
            );
        }
        let (name, value) = pair
            .split_once('=')
            .ok_or("Each form field needs name=value; edited bytes are not a valid lab form.")?;
        let name = decode(name)?;
        let value = decode(value)?;
        match name.as_str() {
            "case" if case.is_none() => case = Some(value),
            "message" if message.is_none() => message = Some(value),
            _ => return Err("Unknown or duplicate field; only case and message are allowed."),
        }
    }
    let case = case.ok_or("Missing case field.")?;
    let message = message.ok_or("Missing message field; message= is an allowed empty value.")?;
    if case.is_empty()
        || case.len() > 32
        || !case
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("Case must be 1–32 ASCII letters, digits, hyphens or underscores.");
    }
    if message.len() > 256 {
        return Err("Message exceeds 256 UTF-8 bytes (not characters).");
    }
    Ok(Fields { case, message })
}

fn decode(value: &str) -> Result<String, &'static str> {
    for (index, byte) in value.bytes().enumerate() {
        if byte == b'%'
            && !value
                .as_bytes()
                .get(index + 1..index + 3)
                .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        {
            return Err("Invalid percent escape; expected % followed by two hexadecimal digits.");
        }
    }
    let spaces = value.replace('+', " ");
    percent_decode_str(&spaces)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| "Decoded form field is not UTF-8; received bytes remain authoritative.")
}
