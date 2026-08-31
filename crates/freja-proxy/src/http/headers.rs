use std::{collections::BTreeMap, error::Error, fmt};

use freja_domain::SanitizedHeaders;
use http::{HeaderMap, HeaderName, header};

/// Ambiguous framing, invalid connection tokens, or configured header budget overflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HeaderError {
    BudgetExceeded { observed: usize, maximum: usize },
    TransferEncodingWithContentLength,
    UnsupportedTransferEncoding,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidConnectionToken,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExceeded { observed, maximum } => {
                write!(
                    formatter,
                    "header bytes {observed} exceed configured limit {maximum}"
                )
            }
            Self::TransferEncodingWithContentLength => {
                formatter.write_str("Transfer-Encoding and Content-Length must not appear together")
            }
            Self::UnsupportedTransferEncoding => {
                formatter.write_str("only a single chunked Transfer-Encoding is supported")
            }
            Self::InvalidContentLength => formatter.write_str("invalid Content-Length value"),
            Self::ConflictingContentLength => {
                formatter.write_str("conflicting Content-Length values")
            }
            Self::InvalidConnectionToken => {
                formatter.write_str("Connection header contains an invalid header name")
            }
        }
    }
}

impl Error for HeaderError {}

pub(super) fn validate(headers: &HeaderMap, maximum: usize) -> Result<(), HeaderError> {
    let observed = header_size(headers);
    if observed > maximum {
        return Err(HeaderError::BudgetExceeded { observed, maximum });
    }
    let has_transfer_encoding = headers.contains_key(header::TRANSFER_ENCODING);
    let has_content_length = headers.contains_key(header::CONTENT_LENGTH);
    if has_transfer_encoding && has_content_length {
        return Err(HeaderError::TransferEncodingWithContentLength);
    }
    if has_transfer_encoding {
        validate_transfer_encoding(headers)?;
    }
    if has_content_length {
        validate_content_length(headers)?;
    }
    Ok(())
}

pub(super) fn strip_hop_by_hop(headers: &mut HeaderMap) -> Result<(), HeaderError> {
    let connection_tokens = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(trim_ascii)
        .filter(|token| !token.is_empty())
        .map(|token| HeaderName::from_bytes(token).map_err(|_| HeaderError::InvalidConnectionToken))
        .collect::<Result<Vec<_>, _>>()?;
    for name in connection_tokens {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        HeaderName::from_static("proxy-connection"),
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    Ok(())
}

pub(super) fn policy_headers(headers: &HeaderMap) -> SanitizedHeaders {
    let mut values = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for (name, value) in headers {
        let value = if is_secret_header(name) {
            b"[REDACTED]".to_vec()
        } else {
            value.as_bytes().to_vec()
        };
        values
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value);
    }
    SanitizedHeaders::new(values)
}

fn is_secret_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    )
}

pub(super) fn audit_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        values
            .entry(name.as_str().to_owned())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    values
}

fn header_size(headers: &HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    })
}

fn validate_transfer_encoding(headers: &HeaderMap) -> Result<(), HeaderError> {
    let tokens = headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(trim_ascii)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.len() != 1 || !tokens[0].eq_ignore_ascii_case(b"chunked") {
        return Err(HeaderError::UnsupportedTransferEncoding);
    }
    Ok(())
}

fn validate_content_length(headers: &HeaderMap) -> Result<(), HeaderError> {
    let values = headers
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .map(trim_ascii)
        .collect::<Vec<_>>();
    let mut expected = None;
    for value in values {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(HeaderError::InvalidContentLength);
        }
        let parsed = std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(HeaderError::InvalidContentLength)?;
        if expected.is_some_and(|expected| expected != parsed) {
            return Err(HeaderError::ConflictingContentLength);
        }
        expected = Some(parsed);
    }
    Ok(())
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header};

    use super::{HeaderError, strip_hop_by_hop, validate};

    #[test]
    fn conflicting_framing_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert_eq!(
            validate(&headers, 1_024),
            Err(HeaderError::TransferEncodingWithContentLength)
        );
    }

    #[test]
    fn connection_named_headers_and_proxy_credentials_are_removed() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-remove"));
        headers.insert("x-remove", HeaderValue::from_static("secret"));
        headers.insert(
            header::PROXY_AUTHORIZATION,
            HeaderValue::from_static("Basic secret"),
        );

        strip_hop_by_hop(&mut headers).unwrap();

        assert!(!headers.contains_key("x-remove"));
        assert!(!headers.contains_key(header::PROXY_AUTHORIZATION));
    }
}
