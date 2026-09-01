#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Typed configuration loading, validation, and compilation.
//!
//! Configuration moves through three explicit stages:
//!
//! 1. [`RawConfig`] mirrors the TOML representation.
//! 2. [`ValidatedConfig`] contains values whose local and cross-field
//!    invariants have been checked.
//! 3. [`CompiledConfig`] owns the immutable policy programs consumed by the
//!    runtime.
//!
//! A compiled value is immutable and can be shared between runtime tasks. Raw
//! values must never be used to open listeners or authorize destinations.
//!
//! # Example
//!
//! ```
//! use freja_config::RawConfig;
//!
//! # fn main() -> Result<(), freja_config::ConfigError> {
//! let compiled = RawConfig::parse(r#"
//!     [[listeners]]
//!     kind = "http-forward"
//!     bind = "127.0.0.1:8080"
//! "#)?
//! .validate()?
//! .compile()?;
//!
//! assert_eq!(compiled.listeners().len(), 1);
//! # Ok(())
//! # }
//! ```

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
