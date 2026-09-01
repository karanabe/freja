use base64::{Engine as _, engine::general_purpose::STANDARD};
use freja_domain::ProxyAuthentication;
use http::{HeaderValue, Response, StatusCode, header};
use sha2::{Digest as _, Sha256};

use super::{ProxyBody, ProxyError, full};

pub(super) fn response_for_error(error: ProxyError) -> Result<Response<ProxyBody>, ProxyError> {
    match error {
        ProxyError::PolicyDenied { .. } => Ok(text_response(StatusCode::FORBIDDEN, "forbidden\n")),
        ProxyError::DetourLoop { .. } => Ok(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid TCP detour policy\n",
        )),
        ProxyError::ConnectTimedOut { .. }
        | ProxyError::DnsTimedOut { .. }
        | ProxyError::UpstreamResponseTimedOut => Ok(text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream timeout\n",
        )),
        ProxyError::Dns { .. }
        | ProxyError::NoResolvedAddresses { .. }
        | ProxyError::ConnectFailed { .. }
        | ProxyError::UpstreamHttp { .. }
        | ProxyError::Tls(_) => Ok(text_response(StatusCode::BAD_GATEWAY, "bad gateway\n")),
        ProxyError::Hook(_) | ProxyError::HookMutation(_) => Ok(text_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "hook execution failed\n",
        )),
        ProxyError::InteractiveRejected => Ok(text_response(
            StatusCode::FORBIDDEN,
            "rejected by operator\n",
        )),
        ProxyError::Interactive(_) => Ok(text_response(
            StatusCode::GATEWAY_TIMEOUT,
            "interactive interception failed\n",
        )),
        other => Err(other),
    }
}

pub(super) fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let mut response = Response::new(full(message.to_owned()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

pub(super) fn authenticate_proxy_request(
    headers: &http::HeaderMap,
    authentication: &ProxyAuthentication,
) -> bool {
    let mut values = headers.get_all(header::PROXY_AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(value) = value.to_str() else {
        return false;
    };
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return false;
    }
    let Ok(mut credential) = STANDARD.decode(encoded) else {
        return false;
    };
    let candidate = Sha256::digest(&credential);
    credential.fill(0);
    constant_time_equal(
        candidate.as_slice(),
        authentication.credential_hash().as_bytes(),
    )
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(super) fn proxy_authentication_required(
    authentication: &ProxyAuthentication,
) -> Response<ProxyBody> {
    let mut response = text_response(
        StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        "proxy authentication required\n",
    );
    if let Ok(challenge) = HeaderValue::from_str(&format!(
        "Basic realm=\"{}\", charset=\"UTF-8\"",
        authentication.realm()
    )) {
        response
            .headers_mut()
            .insert(header::PROXY_AUTHENTICATE, challenge);
    }
    response
}
