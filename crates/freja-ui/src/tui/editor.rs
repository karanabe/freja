use std::{collections::HashSet, error::Error, fmt};

use freja_policy::hook::{
    BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HttpRequestMutationPlan,
    HttpRequestSnapshot, InteractiveDecision, MutationError, apply_head_mutation,
    normalize_replaced_body_headers,
};
use http::{HeaderMap, HeaderName, HeaderValue, Version, header};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EditorMode {
    Normal,
    Insert,
}

#[derive(Debug)]
pub(super) struct RequestEditor {
    original_method: String,
    original_target: String,
    original_headers: HeaderMap,
    original_body: Vec<u8>,
    maximum_head_bytes: usize,
    maximum_body_bytes: usize,
    maximum_document_bytes: usize,
    buffer: String,
    cursor: usize,
    mode: EditorMode,
    status: String,
}

pub(super) struct RequestEditSubmission {
    pub(super) decision: InteractiveDecision,
    pub(super) header_map: HeaderMap,
    pub(super) headers: Vec<(String, Vec<u8>)>,
    pub(super) body: Vec<u8>,
}

#[derive(Debug)]
pub(super) enum RequestEditError {
    UnsupportedVersion,
    NonTextHeader(HeaderName),
    NonTextBody,
    DocumentTooLarge { actual: usize, maximum: usize },
    Incomplete,
    Parse(httparse::Error),
    ChangedStartLine,
    InvalidHeaderName(http::header::InvalidHeaderName),
    InvalidHeaderValue(http::header::InvalidHeaderValue),
    HeadTooLarge { actual: usize, maximum: usize },
    BodyTooLarge { actual: usize, maximum: usize },
    Mutation(MutationError),
}

impl fmt::Display for RequestEditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                formatter.write_str("the request editor supports HTTP/1.1 only")
            }
            Self::NonTextHeader(name) => {
                write!(formatter, "header {name} is not editable UTF-8 text")
            }
            Self::NonTextBody => formatter.write_str("the request body is not editable UTF-8 text"),
            Self::DocumentTooLarge { actual, maximum } => write!(
                formatter,
                "edited request contains {actual} bytes, exceeding the editor limit {maximum}"
            ),
            Self::Incomplete => formatter.write_str("request head must end with a blank line"),
            Self::Parse(_) => formatter.write_str("edited request is not valid HTTP/1.1 syntax"),
            Self::ChangedStartLine => formatter.write_str(
                "method, request target, and HTTP version are read-only in the request editor",
            ),
            Self::InvalidHeaderName(_) => {
                formatter.write_str("edited request has an invalid header name")
            }
            Self::InvalidHeaderValue(_) => {
                formatter.write_str("edited request has an invalid header value")
            }
            Self::HeadTooLarge { actual, maximum } => write!(
                formatter,
                "edited request headers contain {actual} bytes, exceeding the configured limit {maximum}"
            ),
            Self::BodyTooLarge { actual, maximum } => write!(
                formatter,
                "edited request body contains {actual} bytes, exceeding the configured limit {maximum}"
            ),
            Self::Mutation(error) => write!(formatter, "edited request is not permitted: {error}"),
        }
    }
}

impl Error for RequestEditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Parse(source) => Some(source),
            Self::InvalidHeaderName(source) => Some(source),
            Self::InvalidHeaderValue(source) => Some(source),
            Self::Mutation(source) => Some(source),
            Self::UnsupportedVersion
            | Self::NonTextHeader(_)
            | Self::NonTextBody
            | Self::DocumentTooLarge { .. }
            | Self::Incomplete
            | Self::ChangedStartLine
            | Self::HeadTooLarge { .. }
            | Self::BodyTooLarge { .. } => None,
        }
    }
}

impl RequestEditor {
    pub(super) fn new(snapshot: &HttpRequestSnapshot) -> Result<Self, RequestEditError> {
        if snapshot.version != Version::HTTP_11 {
            return Err(RequestEditError::UnsupportedVersion);
        }
        let start_line = format!("{} {} HTTP/1.1", snapshot.method, snapshot.uri);
        let mut buffer = format!("{start_line}\n");
        for (name, value) in &snapshot.headers {
            let value = value
                .to_str()
                .map_err(|_| RequestEditError::NonTextHeader(name.clone()))?;
            buffer.push_str(name.as_str());
            buffer.push_str(": ");
            buffer.push_str(value);
            buffer.push('\n');
        }
        buffer.push('\n');
        let cursor = buffer.len();
        let body = std::str::from_utf8(snapshot.body.bytes())
            .map_err(|_| RequestEditError::NonTextBody)?;
        buffer.push_str(body);
        let maximum_document_bytes = snapshot
            .maximum_head_bytes
            .saturating_add(snapshot.maximum_body_bytes)
            .saturating_add(start_line.len())
            .saturating_add(2);
        if buffer.len() > maximum_document_bytes {
            return Err(RequestEditError::DocumentTooLarge {
                actual: buffer.len(),
                maximum: maximum_document_bytes,
            });
        }
        Ok(Self {
            original_method: snapshot.method.as_str().to_owned(),
            original_target: snapshot.uri.to_string(),
            original_headers: snapshot.headers.clone(),
            original_body: snapshot.body.bytes().to_vec(),
            maximum_head_bytes: snapshot.maximum_head_bytes,
            maximum_body_bytes: snapshot.maximum_body_bytes,
            maximum_document_bytes,
            buffer,
            cursor,
            mode: EditorMode::Normal,
            status: "NORMAL — i insert | s submit | q discard".to_owned(),
        })
    }

    pub(super) const fn mode(&self) -> EditorMode {
        self.mode
    }

    pub(super) fn enter_insert_mode(&mut self) {
        self.mode = EditorMode::Insert;
        "INSERT — Esc normal | Enter newline | Ctrl+S submit".clone_into(&mut self.status);
    }

    pub(super) fn enter_normal_mode(&mut self) {
        self.mode = EditorMode::Normal;
        "NORMAL — i insert | s submit | q discard".clone_into(&mut self.status);
    }

    pub(super) fn status(&self) -> &str {
        &self.status
    }

    pub(super) fn set_error(&mut self, error: &RequestEditError) {
        self.status = format!("ERROR — {error}");
    }

    pub(super) fn display_text(&self) -> String {
        let mut output = self.buffer.clone();
        output.insert(self.cursor, '▏');
        output
    }

    pub(super) fn cursor_line(&self) -> u16 {
        u16::try_from(
            self.buffer[..self.cursor]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count(),
        )
        .unwrap_or(u16::MAX)
    }

    pub(super) fn insert_character(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        let required = character.len_utf8();
        if self.buffer.len().saturating_add(required) > self.maximum_document_bytes {
            self.status = format!(
                "ERROR — request editor limit is {} bytes",
                self.maximum_document_bytes
            );
            return;
        }
        self.buffer.insert(self.cursor, character);
        self.cursor = self.cursor.saturating_add(required);
    }

    pub(super) fn insert_tab(&mut self) {
        self.insert_text("\t");
    }

    pub(super) fn insert_newline(&mut self) {
        self.insert_text("\n");
    }

    fn insert_text(&mut self, text: &str) {
        if self.buffer.len().saturating_add(text.len()) > self.maximum_document_bytes {
            self.status = format!(
                "ERROR — request editor limit is {} bytes",
                self.maximum_document_bytes
            );
            return;
        }
        self.buffer.insert_str(self.cursor, text);
        self.cursor = self.cursor.saturating_add(text.len());
    }

    pub(super) fn backspace(&mut self) {
        let Some(previous) = previous_boundary(&self.buffer, self.cursor) else {
            return;
        };
        self.buffer.drain(previous..self.cursor);
        self.cursor = previous;
    }

    pub(super) fn delete(&mut self) {
        let Some(next) = next_boundary(&self.buffer, self.cursor) else {
            return;
        };
        self.buffer.drain(self.cursor..next);
    }

    pub(super) fn move_left(&mut self) {
        if let Some(previous) = previous_boundary(&self.buffer, self.cursor) {
            self.cursor = previous;
        }
    }

    pub(super) fn move_right(&mut self) {
        if let Some(next) = next_boundary(&self.buffer, self.cursor) {
            self.cursor = next;
        }
    }

    pub(super) fn move_home(&mut self) {
        self.cursor = line_start(&self.buffer, self.cursor);
    }

    pub(super) fn move_end(&mut self) {
        self.cursor = line_end(&self.buffer, self.cursor);
    }

    pub(super) fn move_up(&mut self) {
        let start = line_start(&self.buffer, self.cursor);
        if start == 0 {
            return;
        }
        let column = self.buffer[start..self.cursor].chars().count();
        let previous_end = start.saturating_sub(1);
        let previous_start = line_start(&self.buffer, previous_end);
        self.cursor = byte_at_column(&self.buffer, previous_start, previous_end, column);
    }

    pub(super) fn move_down(&mut self) {
        let end = line_end(&self.buffer, self.cursor);
        if end == self.buffer.len() {
            return;
        }
        let start = line_start(&self.buffer, self.cursor);
        let column = self.buffer[start..self.cursor].chars().count();
        let next_start = end.saturating_add(1);
        let next_end = line_end(&self.buffer, next_start);
        self.cursor = byte_at_column(&self.buffer, next_start, next_end, column);
    }

    pub(super) fn submission(&self) -> Result<RequestEditSubmission, RequestEditError> {
        let (wire, body_offset, header_capacity) = wire_request(&self.buffer)?;
        let mut parsed_headers = vec![httparse::EMPTY_HEADER; header_capacity];
        let mut parsed = httparse::Request::new(&mut parsed_headers);
        let parsed_head_bytes = match parsed.parse(&wire).map_err(RequestEditError::Parse)? {
            httparse::Status::Complete(bytes) => bytes,
            httparse::Status::Partial => return Err(RequestEditError::Incomplete),
        };
        if parsed_head_bytes != body_offset {
            return Err(RequestEditError::Incomplete);
        }
        if parsed.method != Some(self.original_method.as_str())
            || parsed.path != Some(self.original_target.as_str())
            || parsed.version != Some(1)
        {
            return Err(RequestEditError::ChangedStartLine);
        }
        let body = wire[body_offset..].to_vec();
        if body.len() > self.maximum_body_bytes {
            return Err(RequestEditError::BodyTooLarge {
                actual: body.len(),
                maximum: self.maximum_body_bytes,
            });
        }
        let desired_headers = parsed_header_map(&parsed)?;
        validate_header_budget(&desired_headers, self.maximum_head_bytes)?;
        let head = header_diff(&self.original_headers, &desired_headers);
        let mut validated = self.original_headers.clone();
        apply_head_mutation(&mut validated, &head).map_err(RequestEditError::Mutation)?;
        let body_plan = if body == self.original_body {
            BodyMutationPlan::Keep
        } else {
            BodyMutationPlan::Replace(DecodedBody::new(body.clone()))
        };
        let body_replaced = matches!(body_plan, BodyMutationPlan::Replace(_));
        let decision = if head.headers.is_empty() && body_plan == BodyMutationPlan::Keep {
            InteractiveDecision::Continue
        } else {
            InteractiveDecision::ModifyRequest(HttpRequestMutationPlan {
                head,
                body: body_plan,
            })
        };
        let mut display_headers = desired_headers;
        if body_replaced {
            normalize_replaced_body_headers(&mut display_headers);
        }
        display_headers.remove(header::TRANSFER_ENCODING);
        display_headers.remove(header::TRAILER);
        if let Ok(length) = HeaderValue::from_str(&body.len().to_string()) {
            display_headers.insert(header::CONTENT_LENGTH, length);
        }
        validate_header_budget(&display_headers, self.maximum_head_bytes)?;
        let headers = display_headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect();
        Ok(RequestEditSubmission {
            decision,
            header_map: display_headers,
            headers,
            body,
        })
    }
}

fn wire_request(document: &str) -> Result<(Vec<u8>, usize, usize), RequestEditError> {
    let separator = document.find("\n\n").ok_or(RequestEditError::Incomplete)?;
    let body_start = separator.saturating_add(2);
    let mut wire = Vec::with_capacity(document.len().saturating_add(separator));
    let mut line_count = 0_usize;
    for line in document[..separator].split('\n') {
        line_count = line_count.saturating_add(1);
        wire.extend_from_slice(line.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(b"\r\n");
    let body_offset = wire.len();
    wire.extend_from_slice(&document.as_bytes()[body_start..]);
    let header_capacity = line_count.saturating_sub(1).max(1);
    Ok((wire, body_offset, header_capacity))
}

fn parsed_header_map(parsed: &httparse::Request<'_, '_>) -> Result<HeaderMap, RequestEditError> {
    let mut headers = HeaderMap::new();
    for header in parsed.headers.iter() {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(RequestEditError::InvalidHeaderName)?;
        let value =
            HeaderValue::from_bytes(header.value).map_err(RequestEditError::InvalidHeaderValue)?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn header_diff(original: &HeaderMap, desired: &HeaderMap) -> HeadMutationPlan {
    let mut seen = HashSet::new();
    let names = original
        .keys()
        .chain(desired.keys())
        .filter(|name| seen.insert((*name).clone()))
        .cloned()
        .collect::<Vec<_>>();
    let mut mutations = Vec::new();
    for name in names {
        let original_values = header_values(original, &name);
        let desired_values = header_values(desired, &name);
        if original_values == desired_values {
            continue;
        }
        mutations.push(HeaderMutation::Remove { name: name.clone() });
        mutations.extend(desired.get_all(&name).iter().cloned().map(|value| {
            HeaderMutation::Append {
                name: name.clone(),
                value,
            }
        }));
    }
    HeadMutationPlan { headers: mutations }
}

fn header_values(headers: &HeaderMap, name: &HeaderName) -> Vec<Vec<u8>> {
    headers
        .get_all(name)
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect()
}

fn validate_header_budget(headers: &HeaderMap, maximum: usize) -> Result<(), RequestEditError> {
    let actual = headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    });
    if actual > maximum {
        return Err(RequestEditError::HeadTooLarge { actual, maximum });
    }
    Ok(())
}

fn previous_boundary(value: &str, cursor: usize) -> Option<usize> {
    value[..cursor]
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
}

fn next_boundary(value: &str, cursor: usize) -> Option<usize> {
    value[cursor..]
        .chars()
        .next()
        .map(|character| cursor.saturating_add(character.len_utf8()))
}

fn line_start(value: &str, cursor: usize) -> usize {
    value[..cursor]
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1))
}

fn line_end(value: &str, cursor: usize) -> usize {
    value[cursor..]
        .find('\n')
        .map_or(value.len(), |offset| cursor.saturating_add(offset))
}

fn byte_at_column(value: &str, start: usize, end: usize, column: usize) -> usize {
    value[start..end]
        .char_indices()
        .nth(column)
        .map_or(end, |(offset, _)| start.saturating_add(offset))
}

#[cfg(test)]
mod tests {
    use freja_policy::hook::{
        BodyMutationPlan, HeaderMutation, HttpRequestSnapshot, InteractiveDecision, WireBody,
    };
    use http::{HeaderMap, HeaderValue, Method, Uri, Version, header};

    use super::{RequestEditError, RequestEditor};

    #[test]
    fn request_editor_submits_header_and_multiline_body_atomically() {
        let mut editor = RequestEditor::new(&snapshot()).unwrap();
        editor.buffer = concat!(
            "POST /submit HTTP/1.1\n",
            "host: example.test\n",
            "content-length: 3\n",
            "x-review: accepted\n",
            "\n",
            "first\nsecond"
        )
        .to_owned();
        editor.cursor = editor.buffer.len();

        let submission = editor.submission().unwrap();

        let InteractiveDecision::ModifyRequest(plan) = submission.decision else {
            panic!("expected a combined request mutation");
        };
        assert!(plan.head.headers.iter().any(|mutation| matches!(
            mutation,
            HeaderMutation::Append { name, value }
                if name == "x-review" && value == "accepted"
        )));
        assert!(matches!(plan.body, BodyMutationPlan::Replace(_)));
        assert_eq!(submission.body, b"first\nsecond");
        assert!(
            submission
                .headers
                .iter()
                .any(|(name, value)| { name == "content-length" && value.as_slice() == b"12" })
        );
    }

    #[test]
    fn request_editor_rejects_routing_and_protected_header_changes() {
        let mut changed_target = RequestEditor::new(&snapshot()).unwrap();
        changed_target.buffer = changed_target.buffer.replacen("/submit", "/other", 1);
        assert!(matches!(
            changed_target.submission(),
            Err(RequestEditError::ChangedStartLine)
        ));

        let mut changed_host = RequestEditor::new(&snapshot()).unwrap();
        changed_host.buffer =
            changed_host
                .buffer
                .replacen("host: example.test", "host: attacker.test", 1);
        assert!(matches!(
            changed_host.submission(),
            Err(RequestEditError::Mutation(_))
        ));
    }

    fn snapshot() -> HttpRequestSnapshot {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("example.test"));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("3"));
        HttpRequestSnapshot {
            method: Method::POST,
            uri: Uri::from_static("/submit"),
            version: Version::HTTP_11,
            headers,
            body: WireBody::new("old"),
            maximum_head_bytes: 4 * 1_024,
            maximum_body_bytes: 4 * 1_024,
        }
    }
}
