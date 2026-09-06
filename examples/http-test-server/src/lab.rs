//! Fixed-origin browser fixture. Bounds here supplement the existing global
//! request logger/body limit; received data never becomes executable markup.

use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;

use crate::routes::RequestEcho;

mod form;

const MAX_ENCODED_BYTES: usize = 2048;
const MAX_HEADER_BYTES: usize = 1024;
const MAX_HEADERS: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[cfg(feature = "fuzzing")]
pub(super) fn fuzz_form(bytes: &[u8]) {
    if bytes.len() <= MAX_ENCODED_BYTES {
        let _ = form::parse(bytes);
    }
}

pub(super) fn router() -> Router {
    Router::new()
        .route("/lab", get(page))
        .route("/lab/app.js", get(script))
        .route("/lab/style.css", get(style))
        .route("/lab/get", get(receive))
        .route("/lab/post", axum::routing::post(receive))
}

async fn page() -> Response {
    asset("text/html; charset=utf-8", include_str!("lab/index.html"))
}

async fn script() -> Response {
    asset("text/javascript; charset=utf-8", include_str!("lab/app.js"))
}

async fn style() -> Response {
    asset("text/css; charset=utf-8", include_str!("lab/style.css"))
}

fn asset(content_type: &'static str, text: &'static str) -> Response {
    let mut response = text.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    protect(response)
}

fn protect(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
    ));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn receive(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, MAX_ENCODED_BYTES).await else {
        return failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Origin received the request, but the lab body exceeds 2048 bytes or could not be read. No form fields are reported.",
        );
    };
    let query = parts.uri.query().unwrap_or_default();
    let (headers, headers_omitted) = bounded_headers(&parts.headers);
    let mut uri = parts.uri.to_string();
    let uri_omitted = uri.len() > MAX_ENCODED_BYTES;
    uri.truncate(uri.floor_char_boundary(MAX_ENCODED_BYTES));
    let parsed = if query.len() > MAX_ENCODED_BYTES {
        Err((StatusCode::PAYLOAD_TOO_LARGE, "Query exceeds 2048 bytes."))
    } else if parts.method == Method::GET {
        if body.is_empty() {
            form::parse(query.as_bytes()).map_err(|error| (StatusCode::BAD_REQUEST, error))
        } else {
            Err((
                StatusCode::BAD_REQUEST,
                "GET lab input belongs in the query; its body must be empty.",
            ))
        }
    } else if !query.is_empty() {
        Err((
            StatusCode::BAD_REQUEST,
            "POST lab input belongs in the body; its query must be empty.",
        ))
    } else if parts.headers.get(header::CONTENT_ENCODING).is_some() {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Encoded/compressed bodies are not form input for this lab.",
        ))
    } else if !parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|mime| {
                mime.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        })
    {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "POST requires application/x-www-form-urlencoded. Received bytes are shown without form interpretation.",
        ))
    } else {
        form::parse(&body).map_err(|error| (StatusCode::BAD_REQUEST, error))
    };
    let (status, interpretation) = match parsed {
        Ok(fields) => (StatusCode::OK, Interpretation::Fields(fields)),
        Err((status, reason)) => (status, Interpretation::Unavailable { reason }),
    };
    let result = LabReceipt {
        lab: "http11-browser-form",
        arrival: "Origin received this request. Freja traversal is unverified here; correlate its TransactionId in the TUI.",
        http_version: format!("{:?}", parts.version),
        received: RequestEcho::capture(parts.method.as_str(), uri, &headers, &body),
        headers_omitted,
        uri_omitted,
        interpretation,
    };
    // All inputs above are bounded independently. Also enforce the total JSON
    // output contract, including escaping expansion and base64 body metadata.
    match serde_json::to_vec(&result) {
        Ok(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => {
            protect((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response())
        }
        Ok(_) | Err(_) => failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Origin received the request, but its lab display could not be produced within 64 KiB. Check the origin terminal; no automatic retry.",
        ),
    }
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    protect((status, axum::Json(Failure { error: message })).into_response())
}

fn bounded_headers(headers: &HeaderMap) -> (HeaderMap, bool) {
    let mut retained = HeaderMap::new();
    let mut size = 0;
    let mut omitted = false;
    for (name, value) in headers {
        let next = name.as_str().len() + value.as_bytes().len();
        if retained.len() >= MAX_HEADERS || size + next > MAX_HEADER_BYTES {
            omitted = true;
            continue;
        }
        retained.append(name.clone(), value.clone());
        size += next;
    }
    (retained, omitted)
}

#[derive(Serialize)]
struct LabReceipt {
    lab: &'static str,
    arrival: &'static str,
    http_version: String,
    received: RequestEcho,
    headers_omitted: bool,
    uri_omitted: bool,
    interpretation: Interpretation,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Interpretation {
    Fields(form::Fields),
    Unavailable { reason: &'static str },
}

#[derive(Serialize)]
struct Failure {
    error: &'static str,
}
