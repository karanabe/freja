use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy)]
pub(super) enum MessageRole {
    Request,
    Response(ResponseContext),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ResponseContext {
    pub(super) request_was_head: bool,
    pub(super) request_was_connect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WireMessage {
    pub(super) bytes: Vec<u8>,
    pub(super) observed_bytes: u64,
    pub(super) truncated: bool,
    pub(super) informational: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WireFramingError {
    HeadTooLarge { maximum: usize },
    InvalidStartLine,
    InvalidHeaderLine,
    TransferEncodingWithContentLength,
    UnsupportedTransferEncoding,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidChunkSize,
    ChunkSizeOverflow,
    InvalidChunkTerminator,
    TrailersTooLarge { maximum: usize },
    UnexpectedEof,
}

impl fmt::Display for WireFramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeadTooLarge { maximum } => {
                write!(formatter, "HTTP/1 capture head exceeds {maximum} bytes")
            }
            Self::InvalidStartLine => formatter.write_str("invalid HTTP/1 capture start line"),
            Self::InvalidHeaderLine => formatter.write_str("invalid HTTP/1 capture header line"),
            Self::TransferEncodingWithContentLength => formatter
                .write_str("HTTP/1 capture found both Transfer-Encoding and Content-Length"),
            Self::UnsupportedTransferEncoding => formatter
                .write_str("HTTP/1 capture supports only a single chunked Transfer-Encoding"),
            Self::InvalidContentLength => {
                formatter.write_str("invalid HTTP/1 capture Content-Length")
            }
            Self::ConflictingContentLength => {
                formatter.write_str("conflicting HTTP/1 capture Content-Length values")
            }
            Self::InvalidChunkSize => formatter.write_str("invalid HTTP/1 chunk size"),
            Self::ChunkSizeOverflow => formatter.write_str("HTTP/1 chunk size overflow"),
            Self::InvalidChunkTerminator => {
                formatter.write_str("invalid HTTP/1 chunk data terminator")
            }
            Self::TrailersTooLarge { maximum } => {
                write!(formatter, "HTTP/1 capture trailers exceed {maximum} bytes")
            }
            Self::UnexpectedEof => formatter.write_str("incomplete HTTP/1 message at EOF"),
        }
    }
}

impl Error for WireFramingError {}

#[derive(Debug)]
pub(super) enum FramerEvent {
    Started {
        sequence: u64,
    },
    Complete {
        sequence: u64,
        message: WireMessage,
    },
    Failed {
        sequence: u64,
        error: WireFramingError,
    },
}

#[derive(Debug)]
enum State {
    Head,
    FixedBody { remaining: u64, informational: bool },
    ChunkSize { line: Vec<u8> },
    ChunkData { remaining: u64 },
    ChunkDataTerminator { matched: u8 },
    Trailers { line: Vec<u8>, observed: usize },
    CloseDelimited,
    Failed,
}

#[derive(Debug, Clone, Copy)]
enum BodyFraming {
    None { informational: bool },
    Fixed(u64),
    Chunked,
    CloseDelimited,
}

#[derive(Debug)]
pub(super) struct Http1Framer {
    role: MessageRole,
    maximum_head_bytes: usize,
    maximum_capture_bytes: usize,
    state: State,
    sequence: u64,
    active: bool,
    head: Vec<u8>,
    retained: Vec<u8>,
    observed: u64,
    truncated: bool,
}

impl Http1Framer {
    pub(super) fn new(
        role: MessageRole,
        maximum_head_bytes: usize,
        maximum_capture_bytes: usize,
    ) -> Self {
        Self {
            role,
            maximum_head_bytes,
            maximum_capture_bytes,
            state: State::Head,
            sequence: 0,
            active: false,
            head: Vec::new(),
            retained: Vec::new(),
            observed: 0,
            truncated: false,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn push(&mut self, input: &[u8]) -> Vec<FramerEvent> {
        let mut events = Vec::new();
        let mut cursor = 0;
        while cursor < input.len() && !matches!(self.state, State::Failed) {
            if !self.active {
                self.active = true;
                events.push(FramerEvent::Started {
                    sequence: self.sequence,
                });
            }
            match &mut self.state {
                State::Head => {
                    let byte = input[cursor];
                    cursor += 1;
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &[byte],
                    );
                    self.head.push(byte);
                    if self.head.len() > self.maximum_head_bytes {
                        self.fail(
                            WireFramingError::HeadTooLarge {
                                maximum: self.maximum_head_bytes,
                            },
                            &mut events,
                        );
                    } else if self.head.ends_with(b"\r\n\r\n") {
                        match parse_head(&self.head, self.role) {
                            Ok(BodyFraming::None { informational }) => {
                                self.complete(informational, &mut events);
                            }
                            Ok(BodyFraming::Fixed(0)) => self.complete(false, &mut events),
                            Ok(BodyFraming::Fixed(remaining)) => {
                                self.state = State::FixedBody {
                                    remaining,
                                    informational: false,
                                };
                            }
                            Ok(BodyFraming::Chunked) => {
                                self.state = State::ChunkSize { line: Vec::new() };
                            }
                            Ok(BodyFraming::CloseDelimited) => {
                                self.state = State::CloseDelimited;
                            }
                            Err(error) => self.fail(error, &mut events),
                        }
                    }
                }
                State::FixedBody {
                    remaining,
                    informational,
                } => {
                    let available = input.len().saturating_sub(cursor);
                    let count = available.min(usize_from_u64(*remaining));
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &input[cursor..cursor + count],
                    );
                    cursor += count;
                    *remaining = remaining.saturating_sub(u64_from_usize(count));
                    let completed = *remaining == 0;
                    let informational = *informational;
                    if completed {
                        self.complete(informational, &mut events);
                    }
                }
                State::ChunkSize { line } => {
                    let byte = input[cursor];
                    cursor += 1;
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &[byte],
                    );
                    line.push(byte);
                    if line.len() > self.maximum_head_bytes {
                        self.fail(
                            WireFramingError::TrailersTooLarge {
                                maximum: self.maximum_head_bytes,
                            },
                            &mut events,
                        );
                    } else if line.ends_with(b"\r\n") {
                        match parse_chunk_size(&line[..line.len().saturating_sub(2)]) {
                            Ok(0) => {
                                self.state = State::Trailers {
                                    line: Vec::new(),
                                    observed: 0,
                                };
                            }
                            Ok(remaining) => self.state = State::ChunkData { remaining },
                            Err(error) => self.fail(error, &mut events),
                        }
                    }
                }
                State::ChunkData { remaining } => {
                    let available = input.len().saturating_sub(cursor);
                    let count = available.min(usize_from_u64(*remaining));
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &input[cursor..cursor + count],
                    );
                    cursor += count;
                    *remaining = remaining.saturating_sub(u64_from_usize(count));
                    if *remaining == 0 {
                        self.state = State::ChunkDataTerminator { matched: 0 };
                    }
                }
                State::ChunkDataTerminator { matched } => {
                    let expected = if *matched == 0 { b'\r' } else { b'\n' };
                    let byte = input[cursor];
                    cursor += 1;
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &[byte],
                    );
                    if byte != expected {
                        self.fail(WireFramingError::InvalidChunkTerminator, &mut events);
                    } else if *matched == 0 {
                        *matched = 1;
                    } else {
                        self.state = State::ChunkSize { line: Vec::new() };
                    }
                }
                State::Trailers { line, observed } => {
                    let byte = input[cursor];
                    cursor += 1;
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &[byte],
                    );
                    *observed = observed.saturating_add(1);
                    line.push(byte);
                    if *observed > self.maximum_head_bytes {
                        self.fail(
                            WireFramingError::TrailersTooLarge {
                                maximum: self.maximum_head_bytes,
                            },
                            &mut events,
                        );
                    } else if line.ends_with(b"\r\n") {
                        if line.len() == 2 {
                            self.complete(false, &mut events);
                        } else if valid_header_line(&line[..line.len().saturating_sub(2)]) {
                            line.clear();
                        } else {
                            self.fail(WireFramingError::InvalidHeaderLine, &mut events);
                        }
                    }
                }
                State::CloseDelimited => {
                    append_bytes(
                        &mut self.retained,
                        &mut self.observed,
                        &mut self.truncated,
                        self.maximum_capture_bytes,
                        &input[cursor..],
                    );
                    cursor = input.len();
                }
                State::Failed => {}
            }
        }
        events
    }

    pub(super) fn eof(&mut self) -> Vec<FramerEvent> {
        let mut events = Vec::new();
        match self.state {
            State::Head if !self.active => {}
            State::CloseDelimited => self.complete(false, &mut events),
            State::Failed => {}
            _ => self.fail(WireFramingError::UnexpectedEof, &mut events),
        }
        events
    }

    pub(super) fn discard(&mut self) {
        self.state = State::Failed;
        self.active = false;
        self.head.clear();
        self.retained.clear();
        self.observed = 0;
        self.truncated = false;
    }

    fn complete(&mut self, informational: bool, events: &mut Vec<FramerEvent>) {
        events.push(FramerEvent::Complete {
            sequence: self.sequence,
            message: WireMessage {
                bytes: std::mem::take(&mut self.retained),
                observed_bytes: self.observed,
                truncated: self.truncated,
                informational,
            },
        });
        self.reset();
    }

    fn fail(&mut self, error: WireFramingError, events: &mut Vec<FramerEvent>) {
        events.push(FramerEvent::Failed {
            sequence: self.sequence,
            error,
        });
        self.state = State::Failed;
    }

    fn reset(&mut self) {
        self.state = State::Head;
        self.sequence = self.sequence.saturating_add(1);
        self.active = false;
        self.head.clear();
        self.retained.clear();
        self.observed = 0;
        self.truncated = false;
    }
}

fn append_bytes(
    retained: &mut Vec<u8>,
    observed: &mut u64,
    truncated: &mut bool,
    maximum: usize,
    bytes: &[u8],
) {
    *observed = observed.saturating_add(u64_from_usize(bytes.len()));
    let remaining = maximum.saturating_sub(retained.len());
    let count = remaining.min(bytes.len());
    retained.extend_from_slice(&bytes[..count]);
    *truncated |= count < bytes.len();
}

fn parse_head(head: &[u8], role: MessageRole) -> Result<BodyFraming, WireFramingError> {
    let content = head
        .strip_suffix(b"\r\n\r\n")
        .ok_or(WireFramingError::InvalidHeaderLine)?;
    let mut lines = content.split(|byte| *byte == b'\n');
    let start = trim_cr(lines.next().ok_or(WireFramingError::InvalidStartLine)?);
    if start.is_empty() {
        return Err(WireFramingError::InvalidStartLine);
    }
    let mut content_lengths = Vec::new();
    let mut transfer_encodings = Vec::new();
    for raw_line in lines {
        let line = trim_cr(raw_line);
        let Some((name, value)) = split_header(line) else {
            return Err(WireFramingError::InvalidHeaderLine);
        };
        if name.eq_ignore_ascii_case(b"content-length") {
            content_lengths.push(value);
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            transfer_encodings.push(value);
        }
    }
    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(WireFramingError::TransferEncodingWithContentLength);
    }
    let chunked = parse_transfer_encoding(&transfer_encodings)?;
    let content_length = parse_content_length(&content_lengths)?;
    let status = match role {
        MessageRole::Request => None,
        MessageRole::Response(_) => Some(parse_status(start)?),
    };
    if let (MessageRole::Response(context), Some(status)) = (role, status) {
        let informational = (100..200).contains(&status) && status != 101;
        if context.request_was_head
            || informational
            || matches!(status, 101 | 204 | 205 | 304)
            || (context.request_was_connect && (200..300).contains(&status))
        {
            return Ok(BodyFraming::None { informational });
        }
    }
    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    if let Some(length) = content_length {
        return Ok(BodyFraming::Fixed(length));
    }
    match role {
        MessageRole::Request => Ok(BodyFraming::None {
            informational: false,
        }),
        MessageRole::Response(_) => Ok(BodyFraming::CloseDelimited),
    }
}

fn parse_status(start: &[u8]) -> Result<u16, WireFramingError> {
    let mut fields = start.split(|byte| *byte == b' ');
    let version = fields.next().ok_or(WireFramingError::InvalidStartLine)?;
    let status = fields.next().ok_or(WireFramingError::InvalidStartLine)?;
    if !matches!(version, b"HTTP/1.0" | b"HTTP/1.1")
        || status.len() != 3
        || !status.iter().all(u8::is_ascii_digit)
    {
        return Err(WireFramingError::InvalidStartLine);
    }
    std::str::from_utf8(status)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(WireFramingError::InvalidStartLine)
}

fn parse_transfer_encoding(values: &[&[u8]]) -> Result<bool, WireFramingError> {
    if values.is_empty() {
        return Ok(false);
    }
    let tokens = values
        .iter()
        .flat_map(|value| value.split(|byte| *byte == b','))
        .map(trim_ows)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.len() == 1 && tokens[0].eq_ignore_ascii_case(b"chunked") {
        Ok(true)
    } else {
        Err(WireFramingError::UnsupportedTransferEncoding)
    }
}

fn parse_content_length(values: &[&[u8]]) -> Result<Option<u64>, WireFramingError> {
    let mut expected = None;
    for value in values
        .iter()
        .flat_map(|value| value.split(|byte| *byte == b','))
        .map(trim_ows)
    {
        if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
            return Err(WireFramingError::InvalidContentLength);
        }
        let parsed = std::str::from_utf8(value)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(WireFramingError::InvalidContentLength)?;
        if expected.is_some_and(|current| current != parsed) {
            return Err(WireFramingError::ConflictingContentLength);
        }
        expected = Some(parsed);
    }
    Ok(expected)
}

fn parse_chunk_size(line: &[u8]) -> Result<u64, WireFramingError> {
    let digits = line.split(|byte| *byte == b';').next().unwrap_or_default();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(WireFramingError::InvalidChunkSize);
    }
    let mut value = 0_u64;
    for digit in digits {
        let numeric = match digit {
            b'0'..=b'9' => u64::from(*digit - b'0'),
            b'a'..=b'f' => u64::from(*digit - b'a' + 10),
            b'A'..=b'F' => u64::from(*digit - b'A' + 10),
            _ => return Err(WireFramingError::InvalidChunkSize),
        };
        value = value
            .checked_mul(16)
            .and_then(|value| value.checked_add(numeric))
            .ok_or(WireFramingError::ChunkSizeOverflow)?;
    }
    Ok(value)
}

fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let separator = line.iter().position(|byte| *byte == b':')?;
    let name = &line[..separator];
    if name.is_empty()
        || !name.iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return None;
    }
    Some((name, trim_ows(&line[separator.saturating_add(1)..])))
}

fn valid_header_line(line: &[u8]) -> bool {
    split_header(line).is_some()
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len().saturating_sub(1)];
    }
    value
}

fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{FramerEvent, Http1Framer, MessageRole, ResponseContext};

    fn complete_messages(framer: &mut Http1Framer, input: &[u8]) -> Vec<Vec<u8>> {
        framer
            .push(input)
            .into_iter()
            .filter_map(|event| match event {
                FramerEvent::Complete { message, .. } => Some(message.bytes),
                FramerEvent::Started { .. } | FramerEvent::Failed { .. } => None,
            })
            .collect()
    }

    #[test]
    fn content_length_request_is_exact_across_every_split() {
        let input = b"POST / HTTP/1.1\r\nHost: example\r\nContent-Length: 4\r\n\r\ntest";
        for split in 0..=input.len() {
            let mut framer = Http1Framer::new(MessageRole::Request, 1024, 1024);
            let mut messages = complete_messages(&mut framer, &input[..split]);
            messages.extend(complete_messages(&mut framer, &input[split..]));
            assert_eq!(messages, vec![input.to_vec()]);
        }
    }

    #[test]
    fn chunk_extensions_and_trailers_are_framed() {
        let input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\ntest\r\n0\r\nX-End: yes\r\n\r\n";
        for split in 0..=input.len() {
            let mut framer = response_framer();
            let mut messages = complete_messages(&mut framer, &input[..split]);
            messages.extend(complete_messages(&mut framer, &input[split..]));
            assert_eq!(messages, vec![input.to_vec()]);
        }
    }

    #[test]
    fn informational_and_final_responses_are_separate_across_every_split() {
        let informational = b"HTTP/1.1 100 Continue\r\nX-Info: yes\r\n\r\n";
        let final_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut input = informational.to_vec();
        input.extend_from_slice(final_response);
        for split in 0..=input.len() {
            let mut framer = response_framer();
            let mut messages = complete_messages(&mut framer, &input[..split]);
            messages.extend(complete_messages(&mut framer, &input[split..]));
            assert_eq!(
                messages,
                vec![informational.to_vec(), final_response.to_vec()]
            );
        }
    }

    #[test]
    fn ambiguous_capture_framing_fails_without_completing() {
        let input = b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut framer = Http1Framer::new(MessageRole::Request, 1024, 1024);
        let events = framer.push(input);
        assert!(events.iter().any(|event| matches!(
            event,
            FramerEvent::Failed {
                error: super::WireFramingError::TransferEncodingWithContentLength,
                ..
            }
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, FramerEvent::Complete { .. }))
        );
    }

    #[test]
    fn pipelined_requests_are_separate() {
        let first = b"GET /one HTTP/1.1\r\nHost: x\r\n\r\n";
        let second = b"GET /two HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut input = first.to_vec();
        input.extend_from_slice(second);
        let mut framer = Http1Framer::new(MessageRole::Request, 1024, 1024);
        assert_eq!(
            complete_messages(&mut framer, &input),
            vec![first.to_vec(), second.to_vec()]
        );
    }

    #[test]
    fn close_delimited_response_completes_at_eof() {
        let input = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody";
        let mut framer = Http1Framer::new(
            MessageRole::Response(ResponseContext {
                request_was_head: false,
                request_was_connect: false,
            }),
            1024,
            1024,
        );
        assert!(complete_messages(&mut framer, input).is_empty());
        let messages = framer
            .eof()
            .into_iter()
            .filter_map(|event| match event {
                FramerEvent::Complete { message, .. } => Some(message.bytes),
                FramerEvent::Started { .. } | FramerEvent::Failed { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(messages, vec![input.to_vec()]);
    }

    #[test]
    fn capture_retention_truncates_without_losing_framing() {
        let input = b"POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\n12345678";
        let mut framer = Http1Framer::new(MessageRole::Request, 1024, 16);
        let event = framer
            .push(input)
            .into_iter()
            .find_map(|event| match event {
                FramerEvent::Complete { message, .. } => Some(message),
                FramerEvent::Started { .. } | FramerEvent::Failed { .. } => None,
            })
            .unwrap();
        assert_eq!(event.bytes.len(), 16);
        assert_eq!(event.observed_bytes, input.len() as u64);
        assert!(event.truncated);
    }

    fn response_framer() -> Http1Framer {
        Http1Framer::new(
            MessageRole::Response(ResponseContext {
                request_was_head: false,
                request_was_connect: false,
            }),
            1024,
            1024,
        )
    }
}
