use std::{collections::BTreeMap, convert::Infallible, time::Duration};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, Query, Request},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    routing::{any, delete, get, head, options, patch, post, put},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tokio::{sync::mpsc, time::sleep};
use tokio_stream::wrappers::ReceiverStream;

use crate::MAX_REQUEST_BODY_BYTES;

const MAX_DELAY_MILLISECONDS: u64 = 30_000;
const MAX_STREAM_CHUNKS: usize = 1_000;
const MAX_STREAM_INTERVAL_MILLISECONDS: u64 = 1_000;
const MAX_STREAM_DURATION_MILLISECONDS: u64 = 30_000;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const STREAM_CHANNEL_CAPACITY: usize = 1;

pub(super) fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/get", get(echo))
        .route("/post", post(echo))
        .route("/put", put(echo))
        .route("/patch", patch(echo))
        .route("/delete", delete(echo))
        .route("/head", head(echo))
        .route("/options", options(echo))
        .route("/anything", any(echo))
        .route("/anything/{*path}", any(echo))
        .route("/status/{code}", get(status))
        .route("/redirect/{remaining}", get(redirect))
        .route("/delay/{milliseconds}", any(delay))
        .route("/stream/{chunks}", get(stream))
        .route("/bytes/{size}", get(response_bytes))
        .fallback(not_found)
}

async fn index() -> Json<ServerDescription> {
    Json(ServerDescription {
        service: "freja-http-test-server",
        warning: "development-only server; request headers and bodies are echoed",
        endpoints: vec![
            "GET /healthz",
            "GET /get",
            "POST /post",
            "PUT /put",
            "PATCH /patch",
            "DELETE /delete",
            "HEAD /head",
            "OPTIONS /options",
            "ANY /anything/{path}",
            "GET /status/{200..599}",
            "GET /redirect/{0..10}",
            "ANY /delay/{0..30000}",
            "GET /stream/{1..1000}?interval_ms=50",
            "GET /bytes/{0..8388608}",
        ],
    })
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn echo(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => echo_response(
            parts.method.as_str(),
            parts.uri.to_string(),
            &parts.headers,
            &body,
        ),
        Err(error) => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit or could not be read: {error}"
            ),
        ),
    }
}

fn echo_response(method: &str, uri: String, headers: &HeaderMap, body: &Bytes) -> Response {
    let body_utf8 = std::str::from_utf8(body).ok().map(str::to_owned);
    let body_base64 = BASE64.encode(body);
    let mut response = Json(RequestEcho {
        method: method.to_owned(),
        uri,
        headers: capture_headers(headers),
        body: CapturedBody {
            byte_length: body.len(),
            utf8: body_utf8,
            base64: body_base64,
        },
    })
    .into_response();
    response.headers_mut().insert(
        "x-freja-test-server",
        HeaderValue::from_static("request-echo"),
    );
    response
}

fn capture_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut captured = BTreeMap::<String, Vec<String>>::new();
    for (name, value) in headers {
        let value = match value.to_str() {
            Ok(text) => text.to_owned(),
            Err(_) => format!("base64:{}", BASE64.encode(value.as_bytes())),
        };
        captured.entry(name.to_string()).or_default().push(value);
    }
    captured
}

async fn status(Path(code): Path<u16>) -> Response {
    let status = match StatusCode::from_u16(code) {
        Ok(status) if (200..=599).contains(&code) => status,
        Ok(_) | Err(_) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "status code must be between 200 and 599",
            );
        }
    };

    let mut response = if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        Body::empty().into_response()
    } else {
        Json(StatusResponse { status: code }).into_response()
    };
    *response.status_mut() = status;
    response
}

async fn redirect(Path(remaining): Path<u8>) -> Response {
    if remaining > 10 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "redirect count must be between 0 and 10",
        );
    }
    if remaining == 0 {
        return Json(RedirectComplete { redirects: 0 }).into_response();
    }

    Redirect::temporary(&format!("/redirect/{}", remaining - 1)).into_response()
}

async fn delay(Path(milliseconds): Path<u64>, request: Request) -> Response {
    if milliseconds > MAX_DELAY_MILLISECONDS {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("delay must not exceed {MAX_DELAY_MILLISECONDS} milliseconds"),
        );
    }

    sleep(Duration::from_millis(milliseconds)).await;
    echo(request).await
}

async fn stream(Path(chunks): Path<usize>, Query(query): Query<StreamQuery>) -> Response {
    if !(1..=MAX_STREAM_CHUNKS).contains(&chunks) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("chunk count must be between 1 and {MAX_STREAM_CHUNKS}"),
        );
    }
    let interval_milliseconds = query.interval_ms.unwrap_or(50);
    if interval_milliseconds > MAX_STREAM_INTERVAL_MILLISECONDS {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "stream interval must not exceed {MAX_STREAM_INTERVAL_MILLISECONDS} milliseconds"
            ),
        );
    }
    let stream_duration = match u64::try_from(chunks.saturating_sub(1)) {
        Ok(gaps) => gaps.saturating_mul(interval_milliseconds),
        Err(_) => u64::MAX,
    };
    if stream_duration > MAX_STREAM_DURATION_MILLISECONDS {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "total stream duration must not exceed {MAX_STREAM_DURATION_MILLISECONDS} milliseconds"
            ),
        );
    }

    let (sender, receiver) = mpsc::channel::<Result<Bytes, Infallible>>(STREAM_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        for index in 0..chunks {
            let chunk = Bytes::from(format!("chunk-{index:04}\n"));
            if sender.send(Ok(chunk)).await.is_err() {
                break;
            }
            if interval_milliseconds > 0 && index + 1 < chunks {
                sleep(Duration::from_millis(interval_milliseconds)).await;
            }
        }
    });

    let mut response = Body::from_stream(ReceiverStream::new(receiver)).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn response_bytes(Path(size): Path<usize>) -> Response {
    if size > MAX_RESPONSE_BYTES {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("response size must not exceed {MAX_RESPONSE_BYTES} bytes"),
        );
    }

    let mut response = Body::from(vec![b'x'; size]).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "unknown test-server endpoint")
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorMessage {
            error: message.into(),
        }),
    )
        .into_response()
}

#[derive(Serialize)]
struct ServerDescription {
    service: &'static str,
    warning: &'static str,
    endpoints: Vec<&'static str>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct RequestEcho {
    method: String,
    uri: String,
    headers: BTreeMap<String, Vec<String>>,
    body: CapturedBody,
}

#[derive(Serialize)]
struct CapturedBody {
    byte_length: usize,
    utf8: Option<String>,
    base64: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: u16,
}

#[derive(Serialize)]
struct RedirectComplete {
    redirects: u8,
}

#[derive(Deserialize)]
struct StreamQuery {
    interval_ms: Option<u64>,
}

#[derive(Serialize)]
struct ErrorMessage {
    error: String,
}
