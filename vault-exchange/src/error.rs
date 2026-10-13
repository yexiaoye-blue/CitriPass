//! Failures while reading, writing, or selecting an exchange format.

use crate::format::FormatId;

/// Library result.
pub type Result<T> = std::result::Result<T, Error>;

/// A recoverable exchange failure. Match with a wildcard; variants may be added.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// No adapter is registered for this format.
    #[error("format `{0}` is not registered")]
    FormatNotRegistered(FormatId),

    /// An adapter with this format id was already registered on this side.
    #[error("format `{0}` is already registered")]
    FormatAlreadyRegistered(FormatId),

    /// The bytes could not be opened with the supplied credentials.
    ///
    /// The message comes from the format parser. It does not include the password.
    #[error("could not read the source database: {0}")]
    InvalidSource(String),
}
