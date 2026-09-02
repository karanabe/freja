use std::{
    fmt::{self, Display, Formatter, Write as _},
    io::{self, Write as _},
};

use axum::{
    Json,
    body::{Body, Bytes, to_bytes},
    extract::Request,
    http::{HeaderMap, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;

use crate::MAX_REQUEST_BODY_BYTES;

const MAX_LOGGED_BODY_BYTES: usize = 4 * 1024;

pub(super) async fn log_request(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(error) => {
            emit(&RequestLog {
                method: &parts.method,
                uri: &parts.uri,
                headers: &parts.headers,
                body: LoggedBody::Rejected,
            });
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorMessage {
                    error: format!(
                        "request body exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit or could not be read: {error}"
                    ),
                }),
            )
                .into_response();
        }
    };

    emit(&RequestLog {
        method: &parts.method,
        uri: &parts.uri,
        headers: &parts.headers,
        body: LoggedBody::Captured(&body),
    });
    next.run(Request::from_parts(parts, Body::from(body))).await
}

fn emit(log: &RequestLog<'_>) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _result = writeln!(output, "{log}");
}

struct RequestLog<'a> {
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: LoggedBody<'a>,
}

enum LoggedBody<'a> {
    Captured(&'a Bytes),
    Rejected,
}

impl Display for RequestLog<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[received] {} {}",
            EscapedText(self.method.as_str()),
            EscapedText(&self.uri.to_string())
        )?;
        for (name, value) in self.headers {
            write!(formatter, "\n  {name}: ")?;
            if let Ok(text) = value.to_str() {
                write!(formatter, "{}", EscapedText(text))?;
            } else {
                write!(formatter, "base64:{}", BASE64.encode(value.as_bytes()))?;
            }
        }

        match self.body {
            LoggedBody::Captured(body) => format_body(formatter, body),
            LoggedBody::Rejected => write!(
                formatter,
                "\n  body: <rejected; exceeds the {MAX_REQUEST_BODY_BYTES}-byte limit or could not be read>"
            ),
        }
    }
}

fn format_body(formatter: &mut Formatter<'_>, body: &[u8]) -> fmt::Result {
    if body.is_empty() {
        return formatter.write_str("\n  body: 0 bytes <empty>");
    }

    let retained = &body[..body.len().min(MAX_LOGGED_BODY_BYTES)];
    let truncated = body.len() > retained.len();
    if let Ok(text) = std::str::from_utf8(body) {
        let text = utf8_prefix(text, retained.len());
        write!(
            formatter,
            "\n  body: {} bytes, utf-8 preview: {}",
            body.len(),
            EscapedText(text)
        )?;
    } else {
        write!(
            formatter,
            "\n  body: {} bytes, base64 preview: {}",
            body.len(),
            BASE64.encode(retained)
        )?;
    }
    if truncated {
        write!(formatter, " <truncated to {MAX_LOGGED_BODY_BYTES} bytes>")?;
    }
    Ok(())
}

fn utf8_prefix(text: &str, maximum_bytes: usize) -> &str {
    let mut end = text.len().min(maximum_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

struct EscapedText<'a>(&'a str);

impl Display for EscapedText<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            for escaped in character.escape_default() {
                formatter.write_char(escaped)?;
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ErrorMessage {
    error: String,
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Bytes,
        http::{HeaderMap, HeaderValue, Method, Uri},
    };

    use super::{LoggedBody, MAX_LOGGED_BODY_BYTES, RequestLog};

    #[test]
    fn request_log_includes_credentials_and_escapes_terminal_controls() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer secret"));
        headers.insert("cookie", HeaderValue::from_static("session=development"));
        headers.insert("x-note", HeaderValue::from_static("line\tvalue"));
        let body = Bytes::from_static(b"hello\nfreja");
        let uri = "/post?name=freja".parse::<Uri>().unwrap();
        let log = RequestLog {
            method: &Method::POST,
            uri: &uri,
            headers: &headers,
            body: LoggedBody::Captured(&body),
        }
        .to_string();

        assert!(log.starts_with("[received] POST /post?name=freja"));
        assert!(log.contains("authorization: Bearer secret"));
        assert!(log.contains("cookie: session=development"));
        assert!(log.contains("x-note: line\\tvalue"));
        assert!(log.contains("utf-8 preview: hello\\nfreja"));
    }

    #[test]
    fn request_log_bounds_and_base64_encodes_binary_body_preview() {
        let body = Bytes::from(vec![0xff; MAX_LOGGED_BODY_BYTES + 1]);
        let headers = HeaderMap::new();
        let uri = "/post".parse::<Uri>().unwrap();
        let log = RequestLog {
            method: &Method::POST,
            uri: &uri,
            headers: &headers,
            body: LoggedBody::Captured(&body),
        }
        .to_string();

        assert!(log.contains("4097 bytes, base64 preview:"));
        assert!(log.contains("<truncated to 4096 bytes>"));
    }
}
