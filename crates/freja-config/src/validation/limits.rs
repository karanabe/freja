use std::{num::NonZeroUsize, time::Duration};

use crate::{RawLimits, ValidationError};

/// Runtime limits expressed in types and durations rather than raw integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    connections: NonZeroUsize,
    header_bytes: NonZeroUsize,
    body_prefix_bytes: NonZeroUsize,
    connect_timeout: NonZeroDuration,
    read_timeout: NonZeroDuration,
    idle_timeout: NonZeroDuration,
    paused_flows: NonZeroUsize,
    interception_timeout: NonZeroDuration,
    ui_event_capacity: NonZeroUsize,
    ui_content_bytes: NonZeroUsize,
    ui_retained_rows: NonZeroUsize,
}

impl Limits {
    /// Returns the maximum number of concurrently admitted flows.
    pub const fn connections(self) -> usize {
        self.connections.get()
    }

    /// Returns the maximum bytes accepted in one HTTP message head.
    pub const fn header_bytes(self) -> usize {
        self.header_bytes.get()
    }

    /// Returns the maximum bytes retained for body inspection.
    pub const fn body_prefix_bytes(self) -> usize {
        self.body_prefix_bytes.get()
    }

    /// Returns the deadline for establishing an upstream connection.
    pub const fn connect_timeout(self) -> Duration {
        self.connect_timeout.get()
    }

    /// Returns the deadline applied to individual network reads.
    pub const fn read_timeout(self) -> Duration {
        self.read_timeout.get()
    }

    /// Returns the maximum duration without useful flow progress.
    pub const fn idle_timeout(self) -> Duration {
        self.idle_timeout.get()
    }

    /// Returns the maximum simultaneous interactive interceptions.
    pub const fn paused_flows(self) -> usize {
        self.paused_flows.get()
    }

    /// Returns the deadline for an interactive decision.
    pub const fn interception_timeout(self) -> Duration {
        self.interception_timeout.get()
    }

    /// Returns the capacity of the best-effort UI event channel.
    pub const fn ui_event_capacity(self) -> usize {
        self.ui_event_capacity.get()
    }

    /// Returns the maximum payload bytes retained for one TUI traffic side.
    pub const fn ui_content_bytes(self) -> usize {
        self.ui_content_bytes.get()
    }

    /// Returns the maximum transactions or sessions retained by the TUI.
    pub const fn ui_retained_rows(self) -> usize {
        self.ui_retained_rows.get()
    }
}

impl TryFrom<RawLimits> for Limits {
    type Error = ValidationError;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        let connections = nonzero_count("connections", raw.connections)?;
        let header_bytes = nonzero_count("header_bytes", raw.header_bytes)?;
        let body_prefix_bytes = nonzero_count("body_prefix_bytes", raw.body_prefix_bytes)?;
        let paused_flows = nonzero_count("paused_flows", raw.paused_flows)?;
        let ui_event_capacity = nonzero_count("ui_event_capacity", raw.ui_event_capacity)?;
        let ui_content_bytes = nonzero_count("ui_content_bytes", raw.ui_content_bytes)?;
        let ui_retained_rows = nonzero_count("ui_retained_rows", raw.ui_retained_rows)?;
        let connect_timeout =
            NonZeroDuration::from_millis("connect_timeout_ms", raw.connect_timeout_ms)?;
        let read_timeout = NonZeroDuration::from_millis("read_timeout_ms", raw.read_timeout_ms)?;
        let idle_timeout = NonZeroDuration::from_millis("idle_timeout_ms", raw.idle_timeout_ms)?;
        let interception_timeout =
            NonZeroDuration::from_millis("interception_timeout_ms", raw.interception_timeout_ms)?;
        if raw.ui_retained_rows < raw.paused_flows {
            return Err(ValidationError::UiRowsBelowPausedFlows {
                ui_retained_rows: raw.ui_retained_rows,
                paused_flows: raw.paused_flows,
            });
        }
        if raw.header_bytes.checked_add(raw.ui_content_bytes).is_none() {
            return Err(ValidationError::WireCaptureLimitOverflow);
        }

        Ok(Self {
            connections,
            header_bytes,
            body_prefix_bytes,
            connect_timeout,
            read_timeout,
            idle_timeout,
            paused_flows,
            interception_timeout,
            ui_event_capacity,
            ui_content_bytes,
            ui_retained_rows,
        })
    }
}

fn nonzero_count(name: &'static str, value: usize) -> Result<NonZeroUsize, ValidationError> {
    NonZeroUsize::new(value).ok_or(ValidationError::ZeroLimit { name })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NonZeroDuration(Duration);

impl NonZeroDuration {
    fn from_millis(name: &'static str, milliseconds: u64) -> Result<Self, ValidationError> {
        if milliseconds == 0 {
            return Err(ValidationError::ZeroLimit { name });
        }
        Ok(Self(Duration::from_millis(milliseconds)))
    }

    const fn get(self) -> Duration {
        self.0
    }
}
