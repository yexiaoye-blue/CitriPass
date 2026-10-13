//! Device wrap. This record is not part of the syncable vault header.
//! The platform adapter must store the device key and perform local authentication.

use crate::codec::{Buf, Cursor};
use crate::crypto::{self, SealedBlob, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::vault::UnlockedVault;
use crate::wire::SealedVault;
use crate::{Error, InputError, Result};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 4] = b"CPD1";
const VERSION: u16 = 1;

/// 32-byte key held by the platform secure store.
pub struct DeviceKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKey(***)")
    }
}

impl DeviceKey {
    /// Draw a new device key.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(crypto::random_array()?)))
    }

    /// Accept a key previously stored by the platform.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(Error::InvalidInput(InputError::InvalidDeviceKeyLength {
                expected_bytes: KEY_LEN,
            }));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(bytes);
        Ok(Self(Zeroizing::new(key)))
    }

    /// Borrow the raw key for the platform store.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Vault key wrapped for one device.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceUnlock {
    vault_id: Uuid,
    device_id: Uuid,
    wrapped: SealedBlob,
}

impl std::fmt::Debug for DeviceUnlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceUnlock")
            .field("device_id", &self.device_id)
            .finish()
    }
}

impl DeviceUnlock {
    /// Device id bound into this wrap.
    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    /// Encode the wrap.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Buf::with_limit(256);
        buf.push(MAGIC)?;
        buf.u16(VERSION)?;
        buf.push(self.vault_id.as_bytes())?;
        buf.push(self.device_id.as_bytes())?;
        buf.push(&self.wrapped.nonce)?;
        buf.push(&self.wrapped.ciphertext)?;
        buf.push(&self.wrapped.tag)?;
        Ok(buf.finish())
    }

    /// Decode a wrap. Authentication happens on unlock.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 256 {
            return Err(Error::LimitExceeded);
        }
        let mut cursor = Cursor::new(bytes);
        let magic: [u8; 4] = cursor.array()?;
        if &magic != MAGIC || cursor.u16()? != VERSION {
            return Err(Error::UnsupportedFormat);
        }
        let vault_id = Uuid::from_bytes(cursor.array()?);
        let device_id = Uuid::from_bytes(cursor.array()?);
        if vault_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidVaultId));
        }
        if device_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidDeviceId));
        }
        let wrapped = SealedBlob {
            nonce: cursor.array::<NONCE_LEN>()?,
            ciphertext: cursor.take(KEY_LEN)?.to_vec(),
            tag: cursor.array::<TAG_LEN>()?,
        };
        cursor.finish()?;
        Ok(Self {
            vault_id,
            device_id,
            wrapped,
        })
    }
}

impl UnlockedVault {
    /// Wrap the vault key for a device. The result is not written into the vault header.
    pub fn wrap_for_device(&self, key: &DeviceKey, device_id: Uuid) -> Result<DeviceUnlock> {
        if device_id.is_nil() {
            return Err(Error::InvalidInput(InputError::InvalidDeviceId));
        }
        let wrapped = crypto::seal(
            key.as_bytes(),
            &device_aad(self.vault_id(), device_id),
            self.vault_key(),
        )?;
        Ok(DeviceUnlock {
            vault_id: self.vault_id(),
            device_id,
            wrapped,
        })
    }

    /// Open a device wrap for an existing header. This does not replace a platform biometric check.
    pub fn unlock_with_device(
        sealed: &SealedVault,
        record: &DeviceUnlock,
        key: &DeviceKey,
    ) -> Result<Self> {
        if record.vault_id != sealed.vault_id() {
            return Err(Error::InvalidInput(InputError::InvalidVaultId));
        }
        let mut raw = crypto::open(
            key.as_bytes(),
            &device_aad(record.vault_id, record.device_id),
            &record.wrapped,
        )
        .map_err(|error| match error {
            Error::Integrity => Error::UnlockFailed,
            other => other,
        })?;
        if raw.len() != KEY_LEN {
            raw.zeroize();
            return Err(Error::UnlockFailed);
        }
        let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
        vault_key.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self::from_key(sealed.clone(), vault_key))
    }
}

fn device_aad(vault_id: Uuid, device_id: Uuid) -> Vec<u8> {
    let mut aad = b"citripass.device.v1".to_vec();
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(device_id.as_bytes());
    aad
}
