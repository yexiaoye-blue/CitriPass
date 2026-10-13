//! Argon2id and XChaCha20-Poly1305. Wrong passwords still derive a key;
//! only unwrapping the vault key distinguishes them, and that failure is `UnlockFailed`.

use crate::{Error, InputError, Result};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

/// Argon2id memory floor for a new vault, in KiB.
pub const KDF_MEMORY_KIB: u32 = 19 * 1024;
/// Argon2id iteration floor for a new vault.
pub const KDF_ITERATIONS: u32 = 2;
/// Argon2id parallelism used when the caller does not raise it.
pub const KDF_PARALLELISM: u32 = 1;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const SALT_LEN: usize = 16;

/// KDF cost selected by the caller. The salt is chosen by the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfSettings {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2 iteration count.
    pub iterations: u32,
    /// Argon2 lane count.
    pub parallelism: u32,
}

impl Default for KdfSettings {
    fn default() -> Self {
        Self {
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    pub(crate) fn for_creation(settings: KdfSettings) -> Result<Self> {
        if settings.memory_kib < KDF_MEMORY_KIB || settings.iterations < KDF_ITERATIONS {
            return Err(Error::InvalidInput(InputError::WeakKdfParameters {
                min_memory_kib: KDF_MEMORY_KIB,
                min_iterations: KDF_ITERATIONS,
            }));
        }
        let params = Self {
            memory_kib: settings.memory_kib,
            iterations: settings.iterations,
            parallelism: settings.parallelism,
            salt: random_array()?,
        };
        validate_kdf(&params)?;
        Ok(params)
    }

    pub(crate) fn settings(&self) -> KdfSettings {
        KdfSettings {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }

    pub(crate) fn with_new_salt(&self) -> Result<Self> {
        let mut next = self.clone();
        next.salt = random_array()?;
        Ok(next)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SealedBlob {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; TAG_LEN],
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut bytes)
        .map_err(|_| Error::RandomUnavailable)?;
    Ok(bytes)
}

pub(crate) fn random_uuid() -> Result<uuid::Uuid> {
    let mut bytes = random_array::<16>()?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes))
}

pub(crate) fn validate_kdf(params: &KdfParams) -> Result<()> {
    if !(1..=10).contains(&params.iterations) || !(1..=16).contains(&params.parallelism) {
        return Err(Error::UnsupportedFormat);
    }
    let min_memory = params.parallelism.saturating_mul(8);
    if params.memory_kib < min_memory
        || params.memory_kib > 256 * 1024
        || u64::from(params.memory_kib) * u64::from(params.iterations) > 1024 * 1024
    {
        return Err(Error::UnsupportedFormat);
    }
    Ok(())
}

pub(crate) fn derive_kek(password: &str, params: &KdfParams) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    derive_kek_from_secret(password.as_bytes(), params)
}

pub(crate) fn derive_kek_from_secret(
    secret: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    validate_kdf(params)?;
    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Internal)?;
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    let mut memory = Zeroizing::new(vec![argon2::Block::default(); argon.params().block_count()]);
    argon
        .hash_password_into_with_memory(secret, &params.salt, kek.as_mut(), &mut memory)
        .map_err(|_| Error::Internal)?;
    Ok(kek)
}

pub(crate) fn seal(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<SealedBlob> {
    if key.len() != KEY_LEN {
        return Err(Error::Internal);
    }
    if plaintext.len() > crate::limits::MAX_PLAINTEXT {
        return Err(Error::InvalidInput(InputError::PayloadTooLarge {
            max_bytes: crate::limits::MAX_PLAINTEXT,
        }));
    }
    let nonce = random_array()?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Internal)?;
    let mut buffer = Zeroizing::new(plaintext.to_vec());
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buffer)
        .map_err(|_| Error::Internal)?;
    Ok(SealedBlob {
        nonce,
        ciphertext: std::mem::take(&mut *buffer),
        tag: tag.into(),
    })
}

pub(crate) fn open(key: &[u8], aad: &[u8], blob: &SealedBlob) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != KEY_LEN || blob.ciphertext.len() > crate::limits::MAX_PLAINTEXT {
        return Err(Error::Integrity);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Internal)?;
    let mut buffer = Zeroizing::new(blob.ciphertext.clone());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&blob.nonce),
            aad,
            &mut buffer,
            (&blob.tag).into(),
        )
        .map_err(|_| Error::Integrity)?;
    Ok(buffer)
}

/// Authenticate `aad` by encrypting an empty message. The tag covers `aad` only.
pub(crate) fn mac(key: &[u8], aad: &[u8]) -> Result<SealedBlob> {
    let blob = seal(key, aad, &[])?;
    if !blob.ciphertext.is_empty() {
        return Err(Error::Internal);
    }
    Ok(blob)
}

pub(crate) fn verify_mac(key: &[u8], aad: &[u8], blob: &SealedBlob) -> Result<()> {
    if !blob.ciphertext.is_empty() {
        return Err(Error::Integrity);
    }
    let mut opened = open(key, aad, blob)?;
    opened.zeroize();
    Ok(())
}
