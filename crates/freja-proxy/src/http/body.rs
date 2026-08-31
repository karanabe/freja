use std::{
    error::Error,
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use tokio::{sync::mpsc, time::timeout};

use crate::ProxyError;

pub(super) type ProxyBody = UnsyncBoxBody<Bytes, BodyError>;
pub(super) type BodyFrame = Result<Frame<Bytes>, BodyError>;

/// Error surfaced while forwarding or inspecting an HTTP body stream.
#[derive(Debug)]
pub(super) enum BodyError {
    Hyper(hyper::Error),
    ReadTimedOut,
    Inspection(Box<ProxyError>),
    InspectionBlocked,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hyper(_) => formatter.write_str("HTTP body stream failed"),
            Self::ReadTimedOut => formatter.write_str("HTTP body frame read timed out"),
            Self::Inspection(_) => formatter.write_str("HTTP body inspection failed"),
            Self::InspectionBlocked => formatter.write_str("HTTP body was blocked by policy"),
        }
    }
}

impl Error for BodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(source) => Some(source),
            Self::Inspection(source) => Some(source.as_ref()),
            Self::ReadTimedOut | Self::InspectionBlocked => None,
        }
    }
}

pub(super) fn full(bytes: impl Into<Bytes>) -> ProxyBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Creates a bounded body-frame channel for asynchronous inspection pumps.
pub(super) fn channel(capacity: usize) -> (mpsc::Sender<BodyFrame>, ProxyBody) {
    let (sender, receiver) = mpsc::channel(capacity);
    (sender, ChannelBody { receiver }.boxed_unsync())
}

/// Collects one body only while it remains inside an explicit preflight budget.
pub(super) async fn collect_bounded(
    mut body: Incoming,
    maximum: usize,
    read_timeout: Duration,
) -> Result<Bytes, CollectError> {
    let mut bytes = BytesMut::new();
    loop {
        let frame = timeout(read_timeout, body.frame())
            .await
            .map_err(|_| CollectError::ReadTimedOut)?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.map_err(CollectError::Hyper)?;
        if let Ok(data) = frame.into_data() {
            let observed = bytes.len().saturating_add(data.len());
            if observed > maximum {
                return Err(CollectError::LimitExceeded { observed, maximum });
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

#[derive(Debug)]
pub(super) enum CollectError {
    Hyper(hyper::Error),
    ReadTimedOut,
    LimitExceeded { observed: usize, maximum: usize },
}

impl fmt::Display for CollectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hyper(_) => formatter.write_str("HTTP body stream failed during preflight"),
            Self::ReadTimedOut => formatter.write_str("HTTP body frame read timed out"),
            Self::LimitExceeded { observed, maximum } => write!(
                formatter,
                "HTTP body preflight bytes {observed} exceed configured limit {maximum}"
            ),
        }
    }
}

impl Error for CollectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Hyper(source) => Some(source),
            Self::ReadTimedOut | Self::LimitExceeded { .. } => None,
        }
    }
}

struct ChannelBody {
    receiver: mpsc::Receiver<BodyFrame>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.receiver.poll_recv(context)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}
