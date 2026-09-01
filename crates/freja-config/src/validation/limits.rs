use std::time::Duration;

use crate::{RawLimits, ValidationError};

/// Runtime limits expressed in types and durations rather than raw integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum concurrently admitted flows.
    pub connections: usize,
    /// Maximum bytes accepted in one HTTP message head.
    pub header_bytes: usize,
    /// Maximum bytes retained for body inspection.
    pub body_prefix_bytes: usize,
    /// Deadline for establishing an upstream connection.
    pub connect_timeout: Duration,
    /// Deadline applied to individual network reads.
    pub read_timeout: Duration,
    /// Maximum duration without useful flow progress.
    pub idle_timeout: Duration,
    /// Maximum simultaneous interactive interceptions.
    pub paused_flows: usize,
    /// Deadline for an interactive decision.
    pub interception_timeout: Duration,
    /// Capacity of the best-effort UI event channel.
    pub ui_event_capacity: usize,
    /// Maximum payload bytes retained for one TUI traffic side.
    pub ui_content_bytes: usize,
    /// Maximum HTTP transactions or TCP sessions retained by the TUI.
    pub ui_retained_rows: usize,
}

impl TryFrom<RawLimits> for Limits {
    type Error = ValidationError;

    fn try_from(raw: RawLimits) -> Result<Self, Self::Error> {
        validate_nonzero_counts(&raw)?;
        validate_nonzero_timeouts(&raw)?;
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
            connections: raw.connections,
            header_bytes: raw.header_bytes,
            body_prefix_bytes: raw.body_prefix_bytes,
            connect_timeout: Duration::from_millis(raw.connect_timeout_ms),
            read_timeout: Duration::from_millis(raw.read_timeout_ms),
            idle_timeout: Duration::from_millis(raw.idle_timeout_ms),
            paused_flows: raw.paused_flows,
            interception_timeout: Duration::from_millis(raw.interception_timeout_ms),
            ui_event_capacity: raw.ui_event_capacity,
            ui_content_bytes: raw.ui_content_bytes,
            ui_retained_rows: raw.ui_retained_rows,
        })
    }
}

fn validate_nonzero_counts(raw: &RawLimits) -> Result<(), ValidationError> {
    for (name, value) in [
        ("connections", raw.connections),
        ("header_bytes", raw.header_bytes),
        ("body_prefix_bytes", raw.body_prefix_bytes),
        ("paused_flows", raw.paused_flows),
        ("ui_event_capacity", raw.ui_event_capacity),
        ("ui_content_bytes", raw.ui_content_bytes),
        ("ui_retained_rows", raw.ui_retained_rows),
    ] {
        if value == 0 {
            return Err(ValidationError::ZeroLimit { name });
        }
    }
    Ok(())
}

fn validate_nonzero_timeouts(raw: &RawLimits) -> Result<(), ValidationError> {
    for (name, value) in [
        ("connect_timeout_ms", raw.connect_timeout_ms),
        ("read_timeout_ms", raw.read_timeout_ms),
        ("idle_timeout_ms", raw.idle_timeout_ms),
        ("interception_timeout_ms", raw.interception_timeout_ms),
    ] {
        if value == 0 {
            return Err(ValidationError::ZeroLimit { name });
        }
    }
    Ok(())
}
