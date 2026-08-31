#![forbid(unsafe_code)]

//! CLI/bootstrap-only error context.

use std::{error::Error, fmt};

/// Thread-safe boxed error used only at application boundaries.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Application result used by CLI, bootstrap, and task-join boundaries.
pub type AppResult<T> = Result<T, AppError>;

/// Context-preserving application-boundary error.
#[derive(Debug)]
pub struct AppError {
    inner: BoxError,
}

impl AppError {
    /// Boxes a concrete source at the application boundary.
    pub fn new<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self {
            inner: Box::new(error),
        }
    }

    /// Creates an application-boundary error from an operator-facing message.
    pub fn msg(message: impl fmt::Display) -> Self {
        Self::new(MessageError(message.to_string()))
    }

    /// Adds operator-facing context while retaining the source chain.
    #[must_use]
    pub fn context(self, context: impl fmt::Display) -> Self {
        Self::new(ContextError {
            context: context.to_string(),
            source: self.inner,
        })
    }

    /// Returns a concrete inner error when callers need typed handling.
    pub fn downcast_ref<E>(&self) -> Option<&E>
    where
        E: Error + 'static,
    {
        self.inner.as_ref().downcast_ref::<E>()
    }
}

#[derive(Debug)]
struct MessageError(String);

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for MessageError {}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}

#[derive(Debug)]
struct ContextError {
    context: String,
    source: BoxError,
}

impl fmt::Display for ContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.context)
    }
}

impl Error for ContextError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Result extension that adds context without a blanket `From<E>` implementation.
pub trait ResultExt<T> {
    /// Converts a concrete error to [`AppError`] and adds eager context.
    ///
    /// # Errors
    ///
    /// Returns the original error wrapped with `context` when `self` is an error.
    fn context(self, context: impl fmt::Display) -> AppResult<T>;

    /// Converts a concrete error to [`AppError`] and lazily creates context.
    ///
    /// # Errors
    ///
    /// Returns the original error wrapped with generated context when `self`
    /// is an error.
    fn with_context<C, F>(self, context: F) -> AppResult<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Error + Send + Sync + 'static,
{
    fn context(self, context: impl fmt::Display) -> AppResult<T> {
        self.map_err(|error| AppError::new(error).context(context))
    }

    fn with_context<C, F>(self, context: F) -> AppResult<T>
    where
        C: fmt::Display,
        F: FnOnce() -> C,
    {
        self.map_err(|error| AppError::new(error).context(context()))
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error as _, io};

    use super::{AppError, ResultExt as _};

    #[test]
    fn application_error_does_not_repeat_its_display_as_its_source() {
        let error = AppError::new(io::Error::other("disk failure"));

        assert_eq!(error.to_string(), "disk failure");
        assert!(error.source().is_none());
    }

    #[test]
    fn context_exposes_the_original_cause() {
        let error = Err::<(), _>(io::Error::other("disk failure"))
            .context("audit writer failed")
            .unwrap_err();

        assert_eq!(error.to_string(), "audit writer failed");
        assert_eq!(
            error.source().map(ToString::to_string).as_deref(),
            Some("disk failure")
        );
    }
}
