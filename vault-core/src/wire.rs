//! Vault header and item record bytes.
//!
//! A header does not contain items. Each item is its own record so a host can
//! store and sync them independently. Associated data binds the vault, item,
//! revision, and tombstone, and is not stored inside the ciphertext.

use crate::codec::{Buf, Cursor};
use crate::crypto::{self, KdfParams, SealedBlob, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::limits::{MAX_COLLECTION_BYTES, MAX_PLAINTEXT};
use crate::{Error, InputError, Result};
use uuid::Uuid;

const HEADER_MAGIC: &[u8; 4] = b"CPV1";
const ITEM_MAGIC: &[u8; 4] = b"CPI1";
const VERSION: u16 = 1;
const KDF_ARGON2ID: u16 = 1;

/// Ciphertext vault header plus any item records currently loaded in memory.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedVault {
    pub(crate) vault_id: Uuid,
    pub(crate) kdf: KdfParams,
    pub(crate) wrapped_vault_key: SealedBlob,
    pub(crate) recovery: Option<RecoveryWrap>,
    pub(crate) items: Vec<SealedItem>,
}

/// Independent recovery wrap. Its salt and ciphertext are not the master-password wrap.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RecoveryWrap {
    pub kdf: KdfParams,
    pub wrapped_vault_key: SealedBlob,
}

/// One encrypted item record.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedItem {
    pub(crate) vault_id: Uuid,
    pub(crate) item_id: Uuid,
    pub(crate) revision: u64,
    pub(crate) deleted: bool,
    pub(crate) payload: SealedBlob,
}

impl std::fmt::Debug for SealedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedVault")
            .field("vault_id", &self.vault_id)
            .field("items", &self.items.len())
            .finish()
    }
}

impl std::fmt::Debug for SealedItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedItem")
            .field("item_id", &self.item_id)
            .field("revision", &self.revision)
            .field("deleted", &self.deleted)
            .finish()
    }
}

impl SealedVault {
    /// Vault id.
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// KDF cost stored in the header. The salt stays inside the header.
    pub fn kdf_settings(&self) -> crate::KdfSettings {
        self.kdf.settings()
    }

    /// Whether a recovery wrap is present.
    pub fn has_recovery_key(&self) -> bool {
        self.recovery.is_some()
    }

    /// Item records loaded beside this header. Encoding the header omits them.
    pub fn items(&self) -> &[SealedItem] {
        &self.items
    }

    /// Encode the header only.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_header(self)
    }

    /// Decode a header. The result contains no items.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 512 {
            return Err(Error::LimitExceeded);
        }
        decode_header(bytes)
    }
}

impl SealedItem {
    /// Vault that owns the record.
    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Item id.
    pub fn item_id(&self) -> Uuid {
        self.item_id
    }

    /// Authenticated revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Authenticated tombstone flag.
    pub fn deleted(&self) -> bool {
        self.deleted
    }

    /// Encode this record.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_item(self)
    }

    /// Decode one record. Authentication happens when a vault opens it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PLAINTEXT + 128 {
            return Err(Error::LimitExceeded);
        }
        decode_item(bytes)
    }
}

pub(crate) fn item_aad(item: &SealedItem) -> [u8; 58] {
    let label: &[u8; 17] = b"citripass.item.v1";
    let mut aad = [0u8; 58];
    aad[..17].copy_from_slice(label);
    aad[17..33].copy_from_slice(item.vault_id.as_bytes());
    aad[33..49].copy_from_slice(item.item_id.as_bytes());
    aad[49..57].copy_from_slice(&item.revision.to_be_bytes());
    aad[57] = u8::from(item.deleted);
    aad
}

pub(crate) fn vault_key_aad(vault_id: Uuid, recovery: bool) -> Vec<u8> {
    let label: &[u8] = if recovery {
        b"citripass.recovery-key.v1"
    } else {
        b"citripass.vault-key.v1"
    };
    let mut aad = label.to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn encode_header(vault: &SealedVault) -> Result<Vec<u8>> {
    let mut buf = Buf::with_limit(512);
    buf.push(HEADER_MAGIC)?;
    buf.u16(VERSION)?;
    buf.push(vault.vault_id.as_bytes())?;
    write_kdf(&mut buf, &vault.kdf)?;
    write_wrap(&mut buf, &vault.wrapped_vault_key)?;
    match &vault.recovery {
        None => buf.u8(0)?,
        Some(recovery) => {
            buf.u8(1)?;
            write_kdf(&mut buf, &recovery.kdf)?;
            write_wrap(&mut buf, &recovery.wrapped_vault_key)?;
        }
    }
    Ok(buf.finish())
}

fn decode_header(bytes: &[u8]) -> Result<SealedVault> {
    let mut cursor = Cursor::new(bytes);
    let magic: [u8; 4] = cursor.array()?;
    if &magic != HEADER_MAGIC || cursor.u16()? != VERSION {
        return Err(Error::UnsupportedFormat);
    }
    let vault_id = Uuid::from_bytes(cursor.array()?);
    if vault_id.is_nil() {
        return Err(Error::InvalidInput(InputError::InvalidVaultId));
    }
    let kdf = read_kdf(&mut cursor)?;
    crypto::validate_kdf(&kdf)?;
    let wrapped_vault_key = read_wrap(&mut cursor)?;
    let recovery = match cursor.u8()? {
        0 => None,
        1 => {
            let recovery_kdf = read_kdf(&mut cursor)?;
            crypto::validate_kdf(&recovery_kdf)?;
            Some(RecoveryWrap {
                kdf: recovery_kdf,
                wrapped_vault_key: read_wrap(&mut cursor)?,
            })
        }
        _ => return Err(Error::InvalidInput(InputError::MalformedEncoding)),
    };
    cursor.finish()?;
    Ok(SealedVault {
        vault_id,
        kdf,
        wrapped_vault_key,
        recovery,
        items: Vec::new(),
    })
}

fn encode_item(item: &SealedItem) -> Result<Vec<u8>> {
    if item.payload.ciphertext.len() > MAX_PLAINTEXT {
        return Err(Error::LimitExceeded);
    }
    let mut buf = Buf::with_limit(MAX_PLAINTEXT + 128);
    buf.push(ITEM_MAGIC)?;
    buf.u16(VERSION)?;
    buf.push(item.vault_id.as_bytes())?;
    buf.push(item.item_id.as_bytes())?;
    buf.u64(item.revision)?;
    buf.u8(u8::from(item.deleted))?;
    buf.push(&item.payload.nonce)?;
    let length = u32::try_from(item.payload.ciphertext.len()).map_err(|_| Error::LimitExceeded)?;
    buf.u32(length)?;
    buf.push(&item.payload.ciphertext)?;
    buf.push(&item.payload.tag)?;
    Ok(buf.finish())
}

fn decode_item(bytes: &[u8]) -> Result<SealedItem> {
    let mut cursor = Cursor::new(bytes);
    let magic: [u8; 4] = cursor.array()?;
    if &magic != ITEM_MAGIC || cursor.u16()? != VERSION {
        return Err(Error::UnsupportedFormat);
    }
    let vault_id = Uuid::from_bytes(cursor.array()?);
    let item_id = Uuid::from_bytes(cursor.array()?);
    if vault_id.is_nil() {
        return Err(Error::InvalidInput(InputError::InvalidVaultId));
    }
    if item_id.is_nil() {
        return Err(Error::InvalidInput(InputError::InvalidItemId));
    }
    let revision = cursor.u64()?;
    if revision == 0 {
        return Err(Error::InvalidInput(InputError::InvalidRevision));
    }
    let deleted = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidInput(InputError::MalformedEncoding)),
    };
    let nonce = cursor.array()?;
    let length = cursor.u32()? as usize;
    if length > MAX_PLAINTEXT {
        return Err(Error::LimitExceeded);
    }
    let ciphertext = cursor.take(length)?.to_vec();
    let tag = cursor.array()?;
    cursor.finish()?;
    Ok(SealedItem {
        vault_id,
        item_id,
        revision,
        deleted,
        payload: SealedBlob {
            nonce,
            ciphertext,
            tag,
        },
    })
}

fn write_kdf(buf: &mut Buf, kdf: &KdfParams) -> Result<()> {
    buf.u16(KDF_ARGON2ID)?;
    buf.u32(kdf.memory_kib)?;
    buf.u32(kdf.iterations)?;
    buf.u32(kdf.parallelism)?;
    buf.push(&kdf.salt)
}

fn read_kdf(cursor: &mut Cursor<'_>) -> Result<KdfParams> {
    if cursor.u16()? != KDF_ARGON2ID {
        return Err(Error::UnsupportedFormat);
    }
    Ok(KdfParams {
        memory_kib: cursor.u32()?,
        iterations: cursor.u32()?,
        parallelism: cursor.u32()?,
        salt: cursor.array()?,
    })
}

fn write_wrap(buf: &mut Buf, blob: &SealedBlob) -> Result<()> {
    if blob.ciphertext.len() != KEY_LEN {
        return Err(Error::Internal);
    }
    buf.push(&blob.nonce)?;
    buf.push(&blob.ciphertext)?;
    buf.push(&blob.tag)
}

fn read_wrap(cursor: &mut Cursor<'_>) -> Result<SealedBlob> {
    Ok(SealedBlob {
        nonce: cursor.array::<NONCE_LEN>()?,
        ciphertext: cursor.take(KEY_LEN)?.to_vec(),
        tag: cursor.array::<TAG_LEN>()?,
    })
}

pub(crate) fn canonical_backup(header: &[u8], items: &[SealedItem]) -> Result<Vec<u8>> {
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by(|&left, &right| items[left].item_id.cmp(&items[right].item_id));
    let mut buf = Buf::with_limit(MAX_COLLECTION_BYTES);
    let header_len = u32::try_from(header.len()).map_err(|_| Error::LimitExceeded)?;
    buf.u32(header_len)?;
    buf.push(header)?;
    let count = u32::try_from(items.len()).map_err(|_| Error::LimitExceeded)?;
    buf.u32(count)?;
    let mut previous: Option<Uuid> = None;
    for index in order {
        let item = &items[index];
        if previous == Some(item.item_id) {
            return Err(Error::InvalidInput(InputError::DuplicateItemId));
        }
        previous = Some(item.item_id);
        let record = item.to_bytes()?;
        let length = u32::try_from(record.len()).map_err(|_| Error::LimitExceeded)?;
        buf.u32(length)?;
        buf.push(&record)?;
    }
    Ok(buf.finish())
}

/// Split an authenticated backup payload into a header and item records.
pub(crate) fn parse_backup_payload(payload: &[u8]) -> Result<(SealedVault, Vec<SealedItem>)> {
    let mut cursor = Cursor::new(payload);
    let header_len = cursor.u32()? as usize;
    if header_len > 512 {
        return Err(Error::LimitExceeded);
    }
    let header = decode_header(cursor.take(header_len)?)?;
    let count = cursor.u32()? as usize;
    if count > crate::limits::MAX_ITEMS {
        return Err(Error::InvalidInput(InputError::TooManyItems {
            max_items: crate::limits::MAX_ITEMS,
        }));
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let length = cursor.u32()? as usize;
        if length > MAX_PLAINTEXT + 128 {
            return Err(Error::LimitExceeded);
        }
        items.push(decode_item(cursor.take(length)?)?);
    }
    cursor.finish()?;
    Ok((header, items))
}
