//! Errors that stop the pipeline (`DB-006`, #130).
//!
//! Every one of these is fatal. That is the whole point of the issue: py-kms's
//! response to malformed catalogue data is `except KeyError: pass`, so a product
//! silently disappears from the database and the failure surfaces months later
//! as "Server 2022 doesn't work". Here a malformed artifact stops extraction,
//! and a malformed data file stops the build.

use std::fmt;

/// A fatal extraction error, with the context that led to it.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    /// Build an error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// The pipeline's result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Attach context to a failure.
///
/// "no such file" is not an actionable message when the pipeline reads a hundred
/// artifacts; "reading pkeyconfig-csvlk.xrm-ms: no such file" is.
pub trait Context<T> {
    /// Wrap the error with a description of what was being attempted.
    ///
    /// # Errors
    ///
    /// Returns the original error, prefixed with `context`.
    fn context(self, context: impl fmt::Display) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.map_err(|cause| Error::new(format!("{context}: {cause}")))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, context: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::new(context.to_string()))
    }
}
