use std::{
    collections::VecDeque,
    io::IoSlice,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
};

use freja_domain::{Direction, SessionId, TransactionId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::framing::{FramerEvent, Http1Framer, MessageRole, ResponseContext, WireMessage};
use crate::DataPlaneServices;

#[derive(Debug)]
struct RequestRecord {
    sequence: u64,
    transaction_id: Option<TransactionId>,
    result: Option<Result<WireMessage, String>>,
}

#[derive(Debug)]
struct RequestCaptureState {
    framer: Http1Framer,
    records: VecDeque<RequestRecord>,
    dropped_tail: usize,
    maximum_records: usize,
    enabled: bool,
    eof: bool,
}

impl RequestCaptureState {
    fn observe(&mut self, bytes: &[u8], eof: bool) -> Vec<BoundCapture> {
        if !self.enabled || self.eof {
            return Vec::new();
        }
        let mut events = self.framer.push(bytes);
        if eof {
            self.eof = true;
            events.extend(self.framer.eof());
        }
        self.apply_events(events)
    }

    fn apply_events(&mut self, events: Vec<FramerEvent>) -> Vec<BoundCapture> {
        let mut captures = Vec::new();
        for event in events {
            match event {
                FramerEvent::Started { sequence } => {
                    if self.dropped_tail > 0 || self.records.len() == self.maximum_records {
                        self.dropped_tail = self.dropped_tail.saturating_add(1);
                    } else {
                        self.records.push_back(RequestRecord {
                            sequence,
                            transaction_id: None,
                            result: None,
                        });
                    }
                }
                FramerEvent::Complete { sequence, message } => {
                    self.set_result(sequence, Ok(message), &mut captures);
                }
                FramerEvent::Failed { sequence, error } => {
                    self.set_result(sequence, Err(error.to_string()), &mut captures);
                }
            }
        }
        captures
    }

    fn bind(&mut self, transaction_id: TransactionId) -> Vec<BoundCapture> {
        let mut captures = Vec::new();
        if let Some(index) = self
            .records
            .iter()
            .position(|record| record.transaction_id.is_none())
        {
            self.records[index].transaction_id = Some(transaction_id);
            if self.records[index].result.is_some()
                && let Some(record) = self.records.remove(index)
                && let Some(capture) = bound_record(record)
            {
                captures.push(capture);
            }
            return captures;
        }
        if self.dropped_tail > 0 {
            self.dropped_tail = self.dropped_tail.saturating_sub(1);
            captures.push(BoundCapture::Failed {
                transaction_id,
                reason: "HTTP/1 capture correlation limit exceeded".to_owned(),
            });
        } else {
            captures.push(BoundCapture::Failed {
                transaction_id,
                reason: "HTTP/1 capture did not observe a request head".to_owned(),
            });
        }
        captures
    }

    fn set_result(
        &mut self,
        sequence: u64,
        result: Result<WireMessage, String>,
        captures: &mut Vec<BoundCapture>,
    ) {
        let Some(index) = self
            .records
            .iter()
            .position(|record| record.sequence == sequence)
        else {
            return;
        };
        self.records[index].result = Some(result);
        if self.records[index].transaction_id.is_some()
            && let Some(record) = self.records.remove(index)
            && let Some(capture) = bound_record(record)
        {
            captures.push(capture);
        }
    }

    fn abort(&mut self) -> Vec<BoundCapture> {
        self.enabled = false;
        self.eof = true;
        self.framer.discard();
        self.records
            .drain(..)
            .filter_map(|record| {
                record
                    .transaction_id
                    .map(|transaction_id| BoundCapture::Failed {
                        transaction_id,
                        reason: "HTTP/1 request capture ended before message completion".to_owned(),
                    })
            })
            .collect()
    }
}

enum BoundCapture {
    Complete {
        transaction_id: TransactionId,
        message: WireMessage,
    },
    Failed {
        transaction_id: TransactionId,
        reason: String,
    },
}

fn bound_record(record: RequestRecord) -> Option<BoundCapture> {
    let transaction_id = record.transaction_id?;
    match record.result {
        Some(Ok(message)) => Some(BoundCapture::Complete {
            transaction_id,
            message,
        }),
        Some(Err(reason)) => Some(BoundCapture::Failed {
            transaction_id,
            reason,
        }),
        None => Some(BoundCapture::Failed {
            transaction_id,
            reason: "HTTP/1 capture completed without a result".to_owned(),
        }),
    }
}

/// Connection-local handle that correlates parsed requests to raw captures.
#[derive(Debug, Clone)]
pub(crate) struct RequestCaptureHandle {
    state: Arc<Mutex<RequestCaptureState>>,
    services: DataPlaneServices,
    session_id: SessionId,
}

impl RequestCaptureHandle {
    pub(crate) fn bind(&self, transaction_id: TransactionId) {
        let captures = lock(&self.state).bind(transaction_id);
        self.publish(captures);
    }

    pub(crate) fn disable(&self) {
        self.abort();
    }

    fn abort(&self) {
        let captures = lock(&self.state).abort();
        self.publish(captures);
    }

    fn observe(&self, bytes: &[u8], eof: bool) {
        let captures = lock(&self.state).observe(bytes, eof);
        self.publish(captures);
    }

    fn publish(&self, captures: Vec<BoundCapture>) {
        for capture in captures {
            match capture {
                BoundCapture::Complete {
                    transaction_id,
                    message,
                } => self.services.publish_wire_capture(
                    self.session_id,
                    transaction_id,
                    Direction::HttpRequestBody,
                    message.bytes,
                    message.observed_bytes,
                    message.truncated,
                ),
                BoundCapture::Failed {
                    transaction_id,
                    reason,
                } => self.services.publish_wire_capture_failure(
                    self.session_id,
                    transaction_id,
                    Direction::HttpRequestBody,
                    reason,
                ),
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Async I/O adapter that observes downstream HTTP/1 request bytes.
#[derive(Debug)]
pub(crate) struct RequestCaptureIo<S> {
    inner: S,
    handle: RequestCaptureHandle,
}

impl<S> RequestCaptureIo<S> {
    pub(crate) fn new(
        inner: S,
        services: DataPlaneServices,
        session_id: SessionId,
        maximum_head_bytes: usize,
        maximum_content_bytes: usize,
        maximum_records: usize,
    ) -> (Self, RequestCaptureHandle) {
        let maximum_capture_bytes = maximum_head_bytes.saturating_add(maximum_content_bytes);
        let handle = RequestCaptureHandle {
            state: Arc::new(Mutex::new(RequestCaptureState {
                framer: Http1Framer::new(
                    MessageRole::Request,
                    maximum_head_bytes,
                    maximum_capture_bytes,
                ),
                records: VecDeque::new(),
                dropped_tail: 0,
                maximum_records: maximum_records.max(1),
                enabled: true,
                eof: false,
            })),
            services,
            session_id,
        };
        (
            Self {
                inner,
                handle: handle.clone(),
            },
            handle,
        )
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RequestCaptureIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let bytes = &buffer.filled()[before..];
            this.handle.observe(bytes, bytes.is_empty());
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RequestCaptureIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }
}

impl<S> Drop for RequestCaptureIo<S> {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug)]
struct ResponseCapture {
    framer: Http1Framer,
    services: DataPlaneServices,
    session_id: SessionId,
    transaction_id: TransactionId,
    maximum_capture_bytes: usize,
    retained: Vec<u8>,
    observed: u64,
    truncated: bool,
    terminal: bool,
}

impl ResponseCapture {
    fn observe(&mut self, bytes: &[u8], eof: bool) {
        if self.terminal {
            return;
        }
        let mut events = self.framer.push(bytes);
        if eof {
            events.extend(self.framer.eof());
        }
        for event in events {
            match event {
                FramerEvent::Started { .. } => {}
                FramerEvent::Complete { message, .. } => {
                    let informational = message.informational;
                    self.append(&message);
                    if !informational {
                        self.services.publish_wire_capture(
                            self.session_id,
                            self.transaction_id,
                            Direction::HttpResponseBody,
                            std::mem::take(&mut self.retained),
                            self.observed,
                            self.truncated,
                        );
                        self.terminal = true;
                    }
                }
                FramerEvent::Failed { error, .. } => {
                    self.services.publish_wire_capture_failure(
                        self.session_id,
                        self.transaction_id,
                        Direction::HttpResponseBody,
                        error.to_string(),
                    );
                    self.terminal = true;
                }
            }
        }
    }

    fn append(&mut self, message: &WireMessage) {
        self.observed = self.observed.saturating_add(message.observed_bytes);
        let remaining = self
            .maximum_capture_bytes
            .saturating_sub(self.retained.len());
        let count = remaining.min(message.bytes.len());
        self.retained.extend_from_slice(&message.bytes[..count]);
        self.truncated |= message.truncated || count < message.bytes.len();
    }

    fn abort(&mut self) {
        if self.terminal {
            return;
        }
        self.services.publish_wire_capture_failure(
            self.session_id,
            self.transaction_id,
            Direction::HttpResponseBody,
            "HTTP/1 response capture ended before message completion".to_owned(),
        );
        self.terminal = true;
    }
}

/// Async I/O adapter that observes exact upstream HTTP/1 response bytes.
#[derive(Debug)]
pub(crate) struct ResponseCaptureIo<S> {
    inner: S,
    capture: ResponseCapture,
}

impl<S> ResponseCaptureIo<S> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        inner: S,
        services: DataPlaneServices,
        session_id: SessionId,
        transaction_id: TransactionId,
        maximum_head_bytes: usize,
        maximum_content_bytes: usize,
        request_was_head: bool,
        request_was_connect: bool,
    ) -> Self {
        let maximum_capture_bytes = maximum_head_bytes.saturating_add(maximum_content_bytes);
        Self {
            inner,
            capture: ResponseCapture {
                framer: Http1Framer::new(
                    MessageRole::Response(ResponseContext {
                        request_was_head,
                        request_was_connect,
                    }),
                    maximum_head_bytes,
                    maximum_capture_bytes,
                ),
                services,
                session_id,
                transaction_id,
                maximum_capture_bytes,
                retained: Vec::new(),
                observed: 0,
                truncated: false,
                terminal: false,
            },
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseCaptureIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let bytes = &buffer.filled()[before..];
            this.capture.observe(bytes, bytes.is_empty());
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseCaptureIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(context, buffers)
    }
}

impl<S> Drop for ResponseCaptureIo<S> {
    fn drop(&mut self) {
        self.capture.abort();
    }
}
