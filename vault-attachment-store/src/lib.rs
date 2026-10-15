//! Filesystem storage for vault-core encrypted attachment chunks.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use vault_core::{AttachmentEncryptor, SealedAttachment, UnlockedVault, ATTACHMENT_CHUNK_SIZE};

/// Errors raised by the local attachment store.
#[derive(Debug, Error)]
pub enum AttachmentStoreError {
    /// A filesystem operation failed.
    #[error("attachment filesystem error: {0}")]
    Io(#[from] std::io::Error),
    /// vault-core rejected encryption, decryption, or a descriptor.
    #[error("attachment crypto error: {0}")]
    Core(#[from] vault_core::Error),
    /// A chunk was missing or had an unexpected ciphertext length.
    #[error("attachment chunk is missing or malformed: {0}")]
    CorruptChunk(PathBuf),
    /// The target attachment directory already exists.
    #[error("attachment already exists: {0}")]
    AlreadyExists(PathBuf),
    /// A temporary writer has already finished.
    #[error("attachment writer is already finished")]
    Finished,
}

/// Filesystem-backed encrypted attachment store.
#[derive(Clone, Debug)]
pub struct FileAttachmentStore {
    root: PathBuf,
}

impl FileAttachmentStore {
    /// Create the store root and the attachment directory below it.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, AttachmentStoreError> {
        let root = root.into();
        fs::create_dir_all(root.join("attachments"))?;
        Ok(Self { root })
    }

    /// Begin encrypting one attachment into a temporary chunk directory.
    pub fn begin(
        &self,
        vault: &UnlockedVault,
        item_id: uuid::Uuid,
        revision: u64,
        size: u64,
    ) -> Result<FileAttachmentWriter, AttachmentStoreError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| std::io::Error::other("system clock is before Unix epoch"))?
            .as_nanos();
        let temp_dir = self.root.join("attachments").join(format!(
            ".pending-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&temp_dir)?;
        let encryptor = vault.begin_attachment(item_id, revision, size)?;
        Ok(FileAttachmentWriter {
            encryptor: Some(encryptor),
            temp_dir,
            root: self.root.clone(),
            next_chunk: 0,
        })
    }

    /// Read, authenticate, and concatenate every ciphertext chunk.
    pub fn read_all(
        &self,
        vault: &UnlockedVault,
        descriptor: &SealedAttachment,
    ) -> Result<Vec<u8>, AttachmentStoreError> {
        let mut decryptor = vault.open_attachment(descriptor)?;
        let mut output = Vec::with_capacity(
            usize::try_from(descriptor.size())
                .map_err(|_| AttachmentStoreError::Core(vault_core::Error::LimitExceeded))?,
        );
        for index in 0..descriptor.chunk_count() {
            let path = self.chunk_path(descriptor, index);
            let ciphertext = fs::read(&path)?;
            let expected = plaintext_len(descriptor.size(), index)
                .checked_add(16)
                .ok_or_else(|| AttachmentStoreError::CorruptChunk(path.clone()))?;
            if ciphertext.len() != expected {
                return Err(AttachmentStoreError::CorruptChunk(path));
            }
            let plaintext = decryptor.decrypt_chunk(&ciphertext)?;
            output.extend_from_slice(&plaintext);
        }
        decryptor.finish()?;
        Ok(output)
    }

    /// Return the final directory containing one attachment's ciphertext chunks.
    pub fn attachment_dir(&self, descriptor: &SealedAttachment) -> PathBuf {
        self.root
            .join("attachments")
            .join(descriptor.attachment_id().to_string())
    }

    /// Delete an attachment's ciphertext directory. Repeating the operation is allowed.
    pub fn delete(&self, descriptor: &SealedAttachment) -> Result<(), AttachmentStoreError> {
        match fs::remove_dir_all(self.attachment_dir(descriptor)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn chunk_path(&self, descriptor: &SealedAttachment, index: u32) -> PathBuf {
        self.attachment_dir(descriptor)
            .join(format!("chunk-{index:08}.bin"))
    }
}

/// One-shot writer for encrypted attachment chunks.
pub struct FileAttachmentWriter {
    encryptor: Option<AttachmentEncryptor>,
    temp_dir: PathBuf,
    root: PathBuf,
    next_chunk: u32,
}

impl FileAttachmentWriter {
    /// Encrypt and fsync the next plaintext chunk.
    pub fn write_chunk(&mut self, plaintext: &[u8]) -> Result<(), AttachmentStoreError> {
        let encryptor = self
            .encryptor
            .as_mut()
            .ok_or(AttachmentStoreError::Finished)?;
        let ciphertext = encryptor.encrypt_chunk(plaintext)?;
        let path = self
            .temp_dir
            .join(format!("chunk-{:08}.bin", self.next_chunk));
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        self.next_chunk += 1;
        Ok(())
    }

    /// Finish encryption and atomically publish the chunk directory.
    pub fn finish(mut self) -> Result<SealedAttachment, AttachmentStoreError> {
        let encryptor = self
            .encryptor
            .take()
            .ok_or(AttachmentStoreError::Finished)?;
        let descriptor = encryptor.finish()?;
        let final_dir = self
            .root
            .join("attachments")
            .join(descriptor.attachment_id().to_string());
        if final_dir.exists() {
            return Err(AttachmentStoreError::AlreadyExists(final_dir));
        }
        fs::rename(&self.temp_dir, &final_dir)?;
        Ok(descriptor)
    }
}

impl Drop for FileAttachmentWriter {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn plaintext_len(size: u64, index: u32) -> usize {
    size.saturating_sub(u64::from(index) * ATTACHMENT_CHUNK_SIZE as u64)
        .min(ATTACHMENT_CHUNK_SIZE as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use vault_core::{ItemData, ItemDraft};

    fn fixture() -> (UnlockedVault, uuid::Uuid, PathBuf) {
        let password = format!("attachment-test-{}", std::process::id());
        let (mut vault, _) = UnlockedVault::create(&password).unwrap();
        let item = vault
            .create_item(ItemDraft::new("Attachment", ItemData::SecureNote))
            .unwrap();
        let root =
            std::env::temp_dir().join(format!("citripass-attachments-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        (vault, item.item_id, root)
    }

    #[test]
    fn encrypted_chunks_roundtrip_and_delete() {
        let (vault, item_id, root) = fixture();
        let store = FileAttachmentStore::new(&root).unwrap();
        let mut writer = store.begin(&vault, item_id, 1, 5).unwrap();
        writer.write_chunk(b"hello").unwrap();
        let descriptor = writer.finish().unwrap();
        assert_eq!(store.read_all(&vault, &descriptor).unwrap(), b"hello");
        assert!(store.attachment_dir(&descriptor).exists());
        store.delete(&descriptor).unwrap();
        assert!(!store.attachment_dir(&descriptor).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_chunk_is_rejected() {
        let (vault, item_id, root) = fixture();
        let store = FileAttachmentStore::new(&root).unwrap();
        let mut writer = store.begin(&vault, item_id, 1, 5).unwrap();
        writer.write_chunk(b"hello").unwrap();
        let descriptor = writer.finish().unwrap();
        let path = store.attachment_dir(&descriptor).join("chunk-00000000.bin");
        let mut ciphertext = fs::read(&path).unwrap();
        ciphertext[0] ^= 1;
        fs::write(&path, ciphertext).unwrap();
        assert!(matches!(
            store.read_all(&vault, &descriptor),
            Err(AttachmentStoreError::Core(vault_core::Error::Integrity))
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
