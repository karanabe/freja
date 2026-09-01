#![forbid(unsafe_code)]

//! Typed configuration loading, validation, and compilation.
//!
//! Configuration moves through three explicit stages:
//!
//! 1. [`RawConfig`] mirrors the TOML representation.
//! 2. [`ValidatedConfig`] contains values whose local and cross-field
//!    invariants have been checked.
//! 3. [`CompiledConfig`] owns the immutable policy programs consumed by the
//!    runtime.

mod compiled;
mod error;
mod raw;
mod validation;

pub use compiled::CompiledConfig;
pub use error::{ConfigError, ValidationError};
pub use raw::{
    RawAudit, RawCapturePolicy, RawConfig, RawInspection, RawInspectionPattern, RawLimits,
    RawListener, RawPolicy, RawProxyAuthentication, RawSafety, RawSocksAuthentication, RawTls,
};
pub use validation::{AuditConfig, CapturePolicy, Limits, TlsConfig, ValidatedConfig};
