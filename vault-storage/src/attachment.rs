//! Attachment content port.
//!
//! The driver stores ciphertext chunks. It does not decide when a descriptor
//! or item reference becomes durable. [`crate::VaultSession`] makes that decision.

use std::error::Error as StdError;

use uuid::Uuid;
use vault_core::{SealedAttachment, UnlockedVault};

/// Driver that stores encrypted attachment chunks.
pub trait AttachmentContent {
    /// Backend-specific failure type.
    type Error: StdError + Send + Sync + 'static;
    /// Writer used to publish one attachment.
    type Writer: AttachmentWriter<Error = Self::Error>;

    /// Begin encrypting one attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the driver or vault-core rejects the attachment.
    fn begin(
        &self,
        vault: &UnlockedVault,
        item_id: Uuid,
        revision: u64,
        size: u64,
    ) -> Result<Self::Writer, Self::Error>;

    /// Read and authenticate every chunk of one attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when a chunk is missing, altered, or fails authentication.
    fn read_all(
        &self,
        vault: &UnlockedVault,
        descriptor: &SealedAttachment,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Delete ciphertext for one attachment. Repeating the operation is allowed.
    ///
    /// # Errors
    ///
    /// Returns an error when the ciphertext cannot be removed.
    fn delete(&self, descriptor: &SealedAttachment) -> Result<(), Self::Error>;
}

/// One-shot writer for a single attachment.
pub trait AttachmentWriter {
    /// Backend-specific failure type.
    type Error: StdError + Send + Sync + 'static;

    /// Encrypt and store the next plaintext chunk.
    ///
    /// # Errors
    ///
    /// Returns an error when the chunk length is wrong or the driver cannot store it.
    fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), Self::Error>;

    /// Finish encryption and publish the ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is incomplete or cannot be published.
    fn finish(self) -> Result<SealedAttachment, Self::Error>;
}
