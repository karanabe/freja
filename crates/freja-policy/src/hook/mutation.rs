use std::{error::Error, fmt};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, header};

use super::{BodyMutationPlan, HeadMutationPlan, HeaderMutation, WireBody};

/// Invalid or unsafe mutation plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    /// A hook attempted to change proxy-controlled routing or framing metadata.
    ProtectedHeader {
        /// Protected header name.
        name: HeaderName,
    },
    /// A replacement exceeded its explicit memory budget.
    BodyTooLarge {
        /// Replacement length in bytes.
        actual: usize,
        /// Configured maximum replacement length in bytes.
        maximum: usize,
    },
    /// A decoded replacement was requested after content encoding was committed.
    EncodedBodyReplacement,
}

impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtectedHeader { name } => {
                write!(
                    formatter,
                    "hook may not mutate proxy-controlled header {name}"
                )
            }
            Self::BodyTooLarge { actual, maximum } => write!(
                formatter,
                "hook replacement body contains {actual} bytes, exceeding the configured limit {maximum}"
            ),
            Self::EncodedBodyReplacement => formatter.write_str(
                "decoded body replacement cannot be applied after content encoding is committed",
            ),
        }
    }
}

impl Error for MutationError {}

/// Applies typed headers and reconstructs body framing after replacement.
///
/// # Errors
///
/// Returns [`MutationError`] when a plan attempts to mutate hop-by-hop framing.
pub fn apply_http_mutation(
    headers: &mut HeaderMap,
    body: &WireBody,
    head: &HeadMutationPlan,
    body_plan: &BodyMutationPlan,
    maximum_replacement_bytes: usize,
) -> Result<Bytes, MutationError> {
    apply_head_mutation(headers, head)?;
    let output = apply_body_mutation(body, body_plan, maximum_replacement_bytes)?;
    if matches!(body_plan, BodyMutationPlan::Replace(_)) {
        normalize_replaced_body_headers(headers);
    }
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::TRAILER);
    if let Ok(length) = HeaderValue::from_str(&output.len().to_string()) {
        headers.insert(header::CONTENT_LENGTH, length);
    }
    Ok(output)
}

/// Removes representation metadata that would make a decoded replacement look
/// like the original encoded body.
pub fn normalize_replaced_body_headers(headers: &mut HeaderMap) {
    headers.remove(header::CONTENT_ENCODING);
    headers.remove(header::CONTENT_RANGE);
    headers.remove(header::ETAG);
    headers.remove("content-md5");
    headers.remove("digest");
}

/// Applies a typed body plan while enforcing the configured replacement bound.
/// An unchanged body is permitted even when an incoming streaming chunk is
/// larger than the replacement budget.
///
/// # Errors
///
/// Returns [`MutationError::BodyTooLarge`] when a replacement exceeds the
/// configured maximum.
pub fn apply_body_mutation(
    body: &WireBody,
    body_plan: &BodyMutationPlan,
    maximum_replacement_bytes: usize,
) -> Result<Bytes, MutationError> {
    match body_plan {
        BodyMutationPlan::Keep => Ok(body.bytes().clone()),
        BodyMutationPlan::Replace(replacement)
            if replacement.bytes().len() > maximum_replacement_bytes =>
        {
            Err(MutationError::BodyTooLarge {
                actual: replacement.bytes().len(),
                maximum: maximum_replacement_bytes,
            })
        }
        BodyMutationPlan::Replace(replacement) => Ok(replacement.bytes().clone()),
    }
}

/// Applies a typed request/response-head plan without altering body framing.
///
/// # Errors
///
/// Returns [`MutationError`] when a plan attempts to mutate hop-by-hop framing.
pub fn apply_head_mutation(
    headers: &mut HeaderMap,
    head: &HeadMutationPlan,
) -> Result<(), MutationError> {
    for mutation in &head.headers {
        match mutation {
            HeaderMutation::Set { name, value } => {
                validate_mutable_header(name)?;
                headers.insert(name, value.clone());
            }
            HeaderMutation::Append { name, value } => {
                validate_mutable_header(name)?;
                headers.append(name, value.clone());
            }
            HeaderMutation::Remove { name } => {
                validate_mutable_header(name)?;
                headers.remove(name);
            }
        }
    }
    Ok(())
}

fn validate_mutable_header(name: &HeaderName) -> Result<(), MutationError> {
    if matches!(
        name.as_str(),
        "connection"
            | "host"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "content-length"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) {
        return Err(MutationError::ProtectedHeader { name: name.clone() });
    }
    Ok(())
}
