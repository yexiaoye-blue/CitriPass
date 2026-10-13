//! Backup snapshot. The header stays readable so the password can derive a key.
//! A detached tag over the header and the sorted item records detects deletion,
//! replacement, and reordering.

use crate::codec::{Buf, Cursor};
use crate::crypto::{self, NONCE_LEN, TAG_LEN};
use crate::limits::MAX_COLLECTION_BYTES;
use crate::vault::UnlockedVault;
use crate::wire;
use crate::{Error, Result};

const MAGIC: &[u8; 4] = b"CPB1";
const VERSION: u16 = 1;

/// Authenticated snapshot of a header and its item records.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBackup {
    payload: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    tag: [u8; TAG_LEN],
}

impl std::fmt::Debug for SealedBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedBackup")
            .field("bytes", &self.payload.len())
            .finish()
    }
}

impl SealedBackup {
    /// Encode the snapshot.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Buf::with_limit(MAX_COLLECTION_BYTES);
        buf.push(MAGIC)?;
        buf.u16(VERSION)?;
        buf.push(&self.payload)?;
        buf.push(&self.nonce)?;
        buf.push(&self.tag)?;
        Ok(buf.finish())
    }

    /// Decode a snapshot. The tag is checked by unlock, after the password unwraps the header.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_COLLECTION_BYTES || bytes.len() < 4 + 2 + NONCE_LEN + TAG_LEN {
            return Err(Error::LimitExceeded);
        }
        let mut cursor = Cursor::new(bytes);
        let magic: [u8; 4] = cursor.array()?;
        if &magic != MAGIC || cursor.u16()? != VERSION {
            return Err(Error::UnsupportedFormat);
        }
        let payload_len = bytes.len() - 4 - 2 - NONCE_LEN - TAG_LEN;
        let payload = cursor.take(payload_len)?.to_vec();
        Ok(Self {
            payload,
            nonce: cursor.array()?,
            tag: cursor.array()?,
        })
    }

    /// Check the snapshot tag, then open the header and every item.
    pub fn unlock(&self, master_password: &str) -> Result<UnlockedVault> {
        let (header, items) = wire::parse_backup_payload(&self.payload)?;
        let mut vault = UnlockedVault::unlock(&header, master_password)?;
        verify(vault.vault_key(), &self.payload, &self.nonce, &self.tag)?;
        for item in items {
            vault.import_item(&item, None)?;
        }
        Ok(vault)
    }
}

impl UnlockedVault {
    /// Build a snapshot of the header and the items in memory.
    pub fn backup(&self) -> Result<SealedBackup> {
        let header = self.header().to_bytes()?;
        let payload = wire::canonical_backup(&header, self.sealed_items())?;
        let mac = crypto::mac(self.vault_key(), &payload)?;
        Ok(SealedBackup {
            payload,
            nonce: mac.nonce,
            tag: mac.tag,
        })
    }
}

fn verify(key: &[u8], payload: &[u8], nonce: &[u8; NONCE_LEN], tag: &[u8; TAG_LEN]) -> Result<()> {
    crypto::verify_mac(
        key,
        payload,
        &crypto::SealedBlob {
            nonce: *nonce,
            ciphertext: Vec::new(),
            tag: *tag,
        },
    )
}
