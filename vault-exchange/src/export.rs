//! Writing an open vault out to another format.

use vault_core::Item;

/// Decrypted records a host wants written to another format.
///
/// The host decrypts them first. This crate does not unlock a vault while exporting.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ExportRequest<'a> {
    /// Password for the destination file, when that format uses one.
    pub password: &'a str,
    /// Items to write. The host chooses the order.
    pub items: &'a [Item],
}

impl<'a> ExportRequest<'a> {
    /// Build a request from items the host has already decrypted.
    pub fn new(password: &'a str, items: &'a [Item]) -> Self {
        Self { password, items }
    }
}

/// Writes decrypted items to one format.
///
/// Register an implementation on [`crate::Catalog`] when a format gains an exporter.
/// No exporter is built in yet.
pub trait Exporter: Send + Sync {
    /// Format this exporter writes.
    fn format_id(&self) -> crate::FormatId;

    /// Serialize `request`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] when the records cannot be represented in this format.
    fn export(&self, request: &ExportRequest<'_>) -> crate::Result<Vec<u8>>;
}
