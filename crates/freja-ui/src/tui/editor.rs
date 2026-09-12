use std::{
    collections::HashSet,
    error::Error,
    fmt,
    sync::atomic::{AtomicU16, Ordering},
};

use freja_policy::hook::{
    BodyMutationPlan, DecodedBody, HeadMutationPlan, HeaderMutation, HttpRequestMutationPlan,
    HttpRequestSnapshot, InteractiveDecision, MutationError, apply_head_mutation,
    normalize_replaced_body_headers,
};
use http::{HeaderMap, HeaderName, HeaderValue, Version, header};
use vim_navigation::{
    Cursor, EditOutcome, EditableBuffer, EditorInput, Motion, MotionKind, Viewport,
};

pub(super) use vim_navigation::Mode as EditorMode;

#[derive(Debug)]
pub(super) struct RequestEditor {
    original_method: String,
    original_target: String,
    original_headers: HeaderMap,
    original_body: Vec<u8>,
    maximum_head_bytes: usize,
    maximum_body_bytes: usize,
    maximum_document_bytes: usize,
    buffer: EditableBuffer,
    // Rendering receives a shared model; the atomic retains the viewport
    // without removing `Sync` from the public `TuiModel`.
    viewport_top: AtomicU16,
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
        let cursor_offset = buffer.len();
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
        let cursor = cursor_at_offset(&buffer, cursor_offset);
        let mut editor_buffer = EditableBuffer::with_byte_limit(
            &buffer,
            Viewport::new(0, 0, 1, 1, 0),
            maximum_document_bytes,
        );
        editor_buffer.set_cursor(cursor);
        Ok(Self {
            original_method: snapshot.method.as_str().to_owned(),
            original_target: snapshot.uri.to_string(),
            original_headers: snapshot.headers.clone(),
            original_body: snapshot.body.bytes().to_vec(),
            maximum_head_bytes: snapshot.maximum_head_bytes,
            maximum_body_bytes: snapshot.maximum_body_bytes,
            maximum_document_bytes,
            buffer: editor_buffer,
            viewport_top: AtomicU16::new(0),
            status: "NORMAL — i insert | s submit | q discard".to_owned(),
        })
    }

    pub(super) const fn mode(&self) -> EditorMode {
        self.buffer.mode()
    }

    pub(super) fn enter_insert_mode(&mut self) {
        let _ = self.buffer.handle(EditorInput::Insert);
        self.set_mode_status();
    }

    pub(super) fn enter_normal_mode(&mut self) {
        let _ = self.buffer.handle(EditorInput::Escape);
        self.set_mode_status();
    }

    pub(super) fn status(&self) -> &str {
        &self.status
    }

    pub(super) fn set_error(&mut self, error: &RequestEditError) {
        self.status = format!("ERROR — {error}");
    }

    #[cfg(test)]
    pub(super) fn document(&self) -> String {
        self.buffer.text()
    }

    pub(super) fn lines(&self) -> &[String] {
        self.buffer.lines()
    }

    pub(super) const fn cursor(&self) -> Cursor {
        self.buffer.cursor()
    }

    pub(super) fn keep_cursor_visible(&self, cursor_row: u16, visible_rows: u16) -> u16 {
        if visible_rows == 0 {
            return self.viewport_top.load(Ordering::Relaxed);
        }
        let mut top = self.viewport_top.load(Ordering::Relaxed);
        if cursor_row < top {
            top = cursor_row;
        } else if cursor_row >= top.saturating_add(visible_rows) {
            top = cursor_row.saturating_sub(visible_rows.saturating_sub(1));
        }
        self.viewport_top.store(top, Ordering::Relaxed);
        top
    }

    pub(super) fn insert_character(&mut self, character: char) {
        if character.is_control() {
            return;
        }
        self.handle_bounded_insert(EditorInput::Character(character), character.len_utf8());
    }

    pub(super) fn insert_tab(&mut self) {
        self.handle_bounded_insert(EditorInput::Character('\t'), 1);
    }

    pub(super) fn insert_newline(&mut self) {
        self.handle_bounded_insert(EditorInput::Newline, 1);
    }

    pub(super) fn backspace(&mut self) {
        let _ = self.buffer.handle(EditorInput::Backspace);
    }

    pub(super) fn delete(&mut self) {
        let _ = self.buffer.handle(EditorInput::Delete);
    }

    pub(super) fn move_left(&mut self) {
        self.move_cursor(MotionKind::Left);
    }

    pub(super) fn move_right(&mut self) {
        self.move_cursor(MotionKind::Right);
    }

    pub(super) fn move_home(&mut self) {
        self.move_cursor(MotionKind::LineStart);
    }

    pub(super) fn move_end(&mut self) {
        self.move_cursor(MotionKind::LineEnd);
    }

    pub(super) fn move_up(&mut self) {
        self.move_cursor(MotionKind::Up);
    }

    pub(super) fn move_down(&mut self) {
        self.move_cursor(MotionKind::Down);
    }

    pub(super) fn submission(&self) -> Result<RequestEditSubmission, RequestEditError> {
        let document = self.buffer.text();
        let (wire, body_offset, header_capacity) = wire_request(&document)?;
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

    fn handle_bounded_insert(&mut self, input: EditorInput, required_bytes: usize) {
        let exceeds_limit = self
            .buffer
            .byte_len()
            .checked_add(required_bytes)
            .is_none_or(|next| next > self.maximum_document_bytes);
        let outcome = self.buffer.handle(input);
        if outcome == EditOutcome::ModeChanged {
            self.set_mode_status();
        } else if outcome == EditOutcome::Ignored && exceeds_limit {
            self.status = format!(
                "ERROR — request editor limit is {} bytes",
                self.maximum_document_bytes
            );
        }
    }

    fn move_cursor(&mut self, motion: MotionKind) {
        if self.buffer.mode() == EditorMode::Normal {
            let _ = self.buffer.handle(EditorInput::Motion(Motion::new(motion)));
            return;
        }
        let cursor = insert_mode_cursor(self.buffer.lines(), self.buffer.cursor(), motion);
        self.buffer.set_cursor(cursor);
    }

    fn set_mode_status(&mut self) {
        match self.buffer.mode() {
            EditorMode::Normal => {
                "NORMAL — i insert | s submit | q discard".clone_into(&mut self.status);
            }
            EditorMode::Insert => {
                "INSERT — Esc/jj normal | Enter newline | Ctrl+S submit"
                    .clone_into(&mut self.status);
            }
        }
    }

    #[cfg(test)]
    fn replace_document(&mut self, document: &str) {
        let cursor = cursor_at_offset(document, document.len());
        self.buffer = EditableBuffer::with_byte_limit(
            document,
            Viewport::new(0, 0, 1, 1, 0),
            self.maximum_document_bytes,
        );
        self.buffer.set_cursor(cursor);
    }

    #[cfg(test)]
    fn constrain_document_to_current_len(&mut self) {
        let document = self.buffer.text();
        let cursor = self.buffer.cursor();
        self.maximum_document_bytes = document.len();
        self.buffer = EditableBuffer::with_byte_limit(
            &document,
            Viewport::new(0, 0, 1, 1, 0),
            self.maximum_document_bytes,
        );
        self.buffer.set_cursor(cursor);
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

fn cursor_at_offset(document: &str, offset: usize) -> Cursor {
    let mut offset = offset.min(document.len());
    while !document.is_char_boundary(offset) {
        offset = offset.saturating_sub(1);
    }
    let prefix = &document[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let byte_column = prefix
        .rfind('\n')
        .map_or(offset, |separator| offset.saturating_sub(separator + 1));
    Cursor::new(line, byte_column)
}

fn insert_mode_cursor(lines: &[String], cursor: Cursor, motion: MotionKind) -> Cursor {
    let line_index = cursor.line().min(lines.len().saturating_sub(1));
    let line = lines.get(line_index).map_or("", String::as_str);
    let byte_column = cursor.byte_column().min(line.len());
    match motion {
        MotionKind::Left if byte_column > 0 => Cursor::new(
            line_index,
            previous_boundary(line, byte_column).unwrap_or(0),
        ),
        MotionKind::Left if line_index > 0 => {
            let previous_line = line_index.saturating_sub(1);
            let previous_length = lines.get(previous_line).map_or(0, String::len);
            Cursor::new(previous_line, previous_length)
        }
        MotionKind::Right if byte_column < line.len() => Cursor::new(
            line_index,
            next_boundary(line, byte_column).unwrap_or(line.len()),
        ),
        MotionKind::Right if line_index.saturating_add(1) < lines.len() => {
            Cursor::new(line_index.saturating_add(1), 0)
        }
        MotionKind::LineStart => Cursor::new(line_index, 0),
        MotionKind::LineEnd => Cursor::new(line_index, line.len()),
        MotionKind::Up if line_index > 0 => {
            let character_column = line.get(..byte_column).unwrap_or_default().chars().count();
            let previous_line = line_index.saturating_sub(1);
            let previous_text = lines.get(previous_line).map_or("", String::as_str);
            Cursor::new(
                previous_line,
                byte_at_character_column(previous_text, character_column),
            )
        }
        MotionKind::Down if line_index.saturating_add(1) < lines.len() => {
            let character_column = line.get(..byte_column).unwrap_or_default().chars().count();
            let next_line = line_index.saturating_add(1);
            let next_text = lines.get(next_line).map_or("", String::as_str);
            Cursor::new(
                next_line,
                byte_at_character_column(next_text, character_column),
            )
        }
        _ => Cursor::new(line_index, byte_column),
    }
}

fn previous_boundary(value: &str, cursor: usize) -> Option<usize> {
    value
        .get(..cursor)?
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
}

fn next_boundary(value: &str, cursor: usize) -> Option<usize> {
    value
        .get(cursor..)?
        .chars()
        .next()
        .map(|character| cursor.saturating_add(character.len_utf8()))
}

fn byte_at_character_column(value: &str, column: usize) -> usize {
    value
        .char_indices()
        .nth(column)
        .map_or(value.len(), |(offset, _)| offset)
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
        editor.replace_document(concat!(
            "POST /submit HTTP/1.1\n",
            "host: example.test\n",
            "content-length: 3\n",
            "x-review: accepted\n",
            "\n",
            "first\nsecond"
        ));

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
        let changed_document = changed_target.document().replacen("/submit", "/other", 1);
        changed_target.replace_document(&changed_document);
        assert!(matches!(
            changed_target.submission(),
            Err(RequestEditError::ChangedStartLine)
        ));

        let mut changed_host = RequestEditor::new(&snapshot()).unwrap();
        let changed_document =
            changed_host
                .document()
                .replacen("host: example.test", "host: attacker.test", 1);
        changed_host.replace_document(&changed_document);
        assert!(matches!(
            changed_host.submission(),
            Err(RequestEditError::Mutation(_))
        ));
    }

    #[test]
    fn request_editor_movement_preserves_a_full_bounded_unicode_draft() {
        let body = "界\nsecond";
        let snapshot = HttpRequestSnapshot {
            method: Method::POST,
            uri: Uri::from_static("/submit"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            body: WireBody::new(body),
            maximum_head_bytes: 4 * 1_024,
            maximum_body_bytes: body.len(),
        };
        let mut editor = RequestEditor::new(&snapshot).unwrap();
        editor.constrain_document_to_current_len();
        let original = editor.document();

        editor.move_right();
        editor.move_down();
        editor.move_up();
        editor.move_left();
        editor.insert_character('X');

        assert_eq!(editor.document(), original);
        assert!(editor.status().contains("request editor limit"));
        assert_eq!(editor.submission().unwrap().body, body.as_bytes());
    }

    #[test]
    fn full_request_editor_still_accepts_jj_escape_without_mutation() {
        let mut editor = RequestEditor::new(&snapshot()).unwrap();
        editor.constrain_document_to_current_len();
        let original = editor.document();
        editor.enter_insert_mode();

        editor.insert_character('j');
        assert_eq!(editor.mode(), super::EditorMode::Insert);
        assert_eq!(editor.document(), original);
        editor.insert_character('j');

        assert_eq!(editor.mode(), super::EditorMode::Normal);
        assert_eq!(editor.document(), original);
        assert!(editor.status().starts_with("NORMAL"));
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
