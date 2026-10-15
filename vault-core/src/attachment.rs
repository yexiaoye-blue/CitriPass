//! XChaCha20-Poly1305 STREAM records.
//!
//! The stored nonce is 19 bytes, not 24. StreamBE32 keeps a 32-bit counter and
//! a one-byte last-block flag in the last 5 bytes of the cipher nonce.

use crate::crypto::{self, SealedBlob, KEY_LEN};
use crate::limits::{ATTACHMENT_CHUNK_SIZE, MAX_ATTACHMENT_SIZE};
use crate::vault::UnlockedVault;
use crate::{Error, InputError, Result};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"CPA1";
const VERSION: u16 = 1;
const ALGORITHM: u16 = 1;
const STREAM_NONCE_LEN: usize = 19;

/// Descriptor for an encrypted attachment. It contains no file name.
#[derive(Clone)]
pub struct SealedAttachment {
    vault_id: Uuid,
    item_id: Uuid,
    attachment_id: Uuid,
    revision: u64,
    size: u64,
    nonce: [u8; STREAM_NONCE_LEN],
    wrapped_key: SealedBlob,
}

impl std::fmt::Debug for SealedAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedAttachment")
            .field("attachment_id", &self.attachment_id)
            .field("size", &self.size)
            .finish()
    }
}

/// One-shot encryption session. A failed or abandoned session cannot be resumed.
pub struct AttachmentEncryptor {
    header: SealedAttachment,
    stream: Option<EncryptorBE32<XChaCha20Poly1305>>,
    next: u32,
}

/// Decryption session. An integrity failure closes it permanently.
pub struct AttachmentDecryptor {
    header: SealedAttachment,
    stream: Option<DecryptorBE32<XChaCha20Poly1305>>,
    next: u32,
}

impl SealedAttachment {
    /// Vault that owns the attachment.
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Attachment id.
    pub fn attachment_id(&self) -> Uuid {
        self.attachment_id
    }
    /// Owning item id.
    pub fn item_id(&self) -> Uuid {
        self.item_id
    }
    /// Authenticated revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Plaintext size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Chunk count. An empty file still has one terminal chunk.
    pub fn chunk_count(&self) -> u32 {
        self.size.div_ceil(ATTACHMENT_CHUNK_SIZE as u64).max(1) as u32
    }

    fn plaintext_len(&self, index: u32) -> usize {
        self.size
            .saturating_sub(u64::from(index) * ATTACHMENT_CHUNK_SIZE as u64)
            .min(ATTACHMENT_CHUNK_SIZE as u64) as usize
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = b"citripass.attachment.v1".to_vec();
        for id in [self.vault_id, self.item_id, self.attachment_id] {
            aad.extend_from_slice(id.as_bytes());
        }
        aad.extend_from_slice(&self.revision.to_be_bytes());
        aad.extend_from_slice(&self.size.to_be_bytes());
        aad.extend_from_slice(&(ATTACHMENT_CHUNK_SIZE as u32).to_be_bytes());
        aad.extend_from_slice(&self.nonce);
        aad
    }

    /// Encode the descriptor.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        use crate::codec::Buf;
        let mut buf = Buf::with_limit(512);
        buf.push(MAGIC)?;
        buf.u16(VERSION)?;
        buf.u16(ALGORITHM)?;
        buf.push(self.vault_id.as_bytes())?;
        buf.push(self.item_id.as_bytes())?;
        buf.push(self.attachment_id.as_bytes())?;
        buf.u64(self.revision)?;
        buf.u64(self.size)?;
        buf.u32(ATTACHMENT_CHUNK_SIZE as u32)?;
        buf.push(&self.nonce)?;
        buf.push(&self.wrapped_key.nonce)?;
        buf.push(&self.wrapped_key.ciphertext)?;
        buf.push(&self.wrapped_key.tag)?;
        Ok(buf.finish())
    }

    /// Decode a descriptor. The wrapped key is checked when the attachment is opened.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use crate::codec::Cursor;
        if bytes.len() > 512 {
            return Err(Error::LimitExceeded);
        }
        let mut cursor = Cursor::new(bytes);
        let magic: [u8; 4] = cursor.array()?;
        if &magic != MAGIC || cursor.u16()? != VERSION || cursor.u16()? != ALGORITHM {
            return Err(Error::UnsupportedFormat);
        }
        let vault_id = Uuid::from_bytes(cursor.array()?);
        let item_id = Uuid::from_bytes(cursor.array()?);
        let attachment_id = Uuid::from_bytes(cursor.array()?);
        if vault_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidVaultId));
        }
        if item_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidItemId));
        }
        if attachment_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidAttachmentId));
        }
        let revision = cursor.u64()?;
        if revision == 0 {
            return Err(Error::InvalidInput(InputError::InvalidRevision));
        }
        let size = cursor.u64()?;
        if size > MAX_ATTACHMENT_SIZE {
            return Err(Error::LimitExceeded);
        }
        if cursor.u32()? != ATTACHMENT_CHUNK_SIZE as u32 {
            return Err(Error::UnsupportedFormat);
        }
        let nonce = cursor.array()?;
        let wrapped_key = SealedBlob {
            nonce: cursor.array()?,
            ciphertext: cursor.take(KEY_LEN)?.to_vec(),
            tag: cursor.array()?,
        };
        cursor.finish()?;
        Ok(Self {
            vault_id,
            item_id,
            attachment_id,
            revision,
            size,
            nonce,
            wrapped_key,
        })
    }
}

impl UnlockedVault {
    /// Start a new attachment. Each call uses a new key and nonce.
    pub fn begin_attachment(
        &self,
        item_id: Uuid,
        revision: u64,
        size: u64,
    ) -> Result<AttachmentEncryptor> {
        let item = self.get_item(item_id)?;
        if item.deleted {
            return Err(Error::InvalidInput(InputError::DeletedItem));
        }
        if revision == 0 {
            return Err(Error::InvalidInput(InputError::InvalidRevision));
        }
        if size > MAX_ATTACHMENT_SIZE {
            return Err(Error::LimitExceeded);
        }
        let key = Zeroizing::new(crypto::random_array::<KEY_LEN>()?);
        let mut header = SealedAttachment {
            vault_id: self.vault_id(),
            item_id,
            attachment_id: crypto::random_uuid()?,
            revision,
            size,
            nonce: crypto::random_array()?,
            wrapped_key: SealedBlob {
                nonce: [0; 24],
                ciphertext: Vec::new(),
                tag: [0; 16],
            },
        };
        header.wrapped_key = crypto::seal(self.vault_key(), &header.aad(), key.as_ref())?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Internal)?;
        Ok(AttachmentEncryptor {
            stream: Some(EncryptorBE32::from_aead(cipher, (&header.nonce).into())),
            header,
            next: 0,
        })
    }

    /// Open a descriptor after checking it against the decrypted owning item.
    pub fn open_attachment_for(
        &self,
        item_id: Uuid,
        header: &SealedAttachment,
    ) -> Result<AttachmentDecryptor> {
        let item = self.get_item(item_id)?;
        if item.deleted {
            return Err(Error::InvalidInput(InputError::DeletedItem));
        }
        if header.item_id != item_id || header.vault_id != self.vault_id() {
            return Err(Error::Integrity);
        }
        let reference = item
            .attachments
            .iter()
            .find(|attachment| attachment.attachment_id == header.attachment_id);
        if reference.map(|attachment| attachment.revision) != Some(header.revision) {
            return Err(Error::Integrity);
        }
        self.open_attachment(header)
    }

    /// Open a descriptor without consulting an item. The caller must select the right one.
    pub fn open_attachment(&self, header: &SealedAttachment) -> Result<AttachmentDecryptor> {
        if header.vault_id != self.vault_id() {
            return Err(Error::Integrity);
        }
        let mut key = crypto::open(self.vault_key(), &header.aad(), &header.wrapped_key)?;
        if key.len() != KEY_LEN {
            key.zeroize();
            return Err(Error::Integrity);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::Internal)?;
        key.zeroize();
        Ok(AttachmentDecryptor {
            stream: Some(DecryptorBE32::from_aead(cipher, (&header.nonce).into())),
            header: header.clone(),
            next: 0,
        })
    }
}

impl AttachmentEncryptor {
    /// Encrypt the next chunk. Its length is determined by the declared file size.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.next >= self.header.chunk_count() {
            return Err(Error::InvalidInput(InputError::AttachmentFinished));
        }
        if plaintext.len() != self.header.plaintext_len(self.next) {
            return Err(Error::InvalidInput(
                InputError::InvalidAttachmentChunkLength {
                    expected_bytes: self.header.plaintext_len(self.next),
                },
            ));
        }
        let mut buffer = Vec::with_capacity(plaintext.len() + 16);
        buffer.extend_from_slice(plaintext);
        let aad = self.header.aad();
        if self.next + 1 == self.header.chunk_count() {
            self.stream
                .take()
                .ok_or(Error::Internal)?
                .encrypt_last_in_place(&aad, &mut buffer)
                .map_err(|_| Error::Internal)?;
        } else {
            self.stream
                .as_mut()
                .ok_or(Error::Internal)?
                .encrypt_next_in_place(&aad, &mut buffer)
                .map_err(|_| Error::Internal)?;
        }
        self.next += 1;
        Ok(std::mem::take(&mut buffer))
    }

    /// Finish only after every chunk, including the terminal chunk, succeeded.
    pub fn finish(self) -> Result<SealedAttachment> {
        if self.next != self.header.chunk_count() {
            return Err(Error::Integrity);
        }
        Ok(self.header)
    }
}

impl AttachmentDecryptor {
    /// Decrypt the next chunk. A bad chunk closes the session.
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.next >= self.header.chunk_count() {
            self.stream.take();
            return Err(Error::Integrity);
        }
        if ciphertext.len() != self.header.plaintext_len(self.next) + 16 {
            self.stream.take();
            return Err(Error::Integrity);
        }
        let mut buffer = ciphertext.to_vec();
        let aad = self.header.aad();
        let opened = if self.next + 1 == self.header.chunk_count() {
            self.stream
                .take()
                .ok_or(Error::Integrity)?
                .decrypt_last_in_place(&aad, &mut buffer)
        } else {
            self.stream
                .as_mut()
                .ok_or(Error::Integrity)?
                .decrypt_next_in_place(&aad, &mut buffer)
        };
        if opened.is_err() {
            self.stream.take();
            return Err(Error::Integrity);
        }
        self.next += 1;
        Ok(Zeroizing::new(buffer))
    }

    /// Finish only after every chunk authenticated.
    pub fn finish(self) -> Result<()> {
        if self.next != self.header.chunk_count() {
            return Err(Error::Integrity);
        }
        Ok(())
    }
}
