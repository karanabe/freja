mod capture;
mod framing;

pub(super) use capture::{RequestCaptureHandle, RequestCaptureIo, ResponseCaptureIo};

/// Exercises the capture-only HTTP/1 framer without exposing it as a parser API.
pub(crate) fn is_valid_capture_framing(input: &[u8]) -> bool {
    let response = |request_was_head, request_was_connect| {
        framing::MessageRole::Response(framing::ResponseContext {
            request_was_head,
            request_was_connect,
        })
    };
    framing_succeeds(framing::MessageRole::Request, input)
        && framing_succeeds(response(false, false), input)
        && framing_succeeds(response(true, false), input)
        && framing_succeeds(response(false, true), input)
}

fn framing_succeeds(role: framing::MessageRole, input: &[u8]) -> bool {
    let mut framer = framing::Http1Framer::new(role, 64 * 1_024, 128 * 1_024);
    let split = input.len() / 2;
    let mut events = framer.push(&input[..split]);
    events.extend(framer.push(&input[split..]));
    events.extend(framer.eof());
    !events
        .iter()
        .any(|event| matches!(event, framing::FramerEvent::Failed { .. }))
}
