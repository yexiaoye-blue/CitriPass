#![doc = include_str!("../GUIDE.md")]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod attachment;
mod backup;
mod codec;
mod crypto;
mod device;
mod error;
mod item;
mod limits;
mod password;
mod recovery;
mod totp;
mod vault;
mod wire;

pub use attachment::{AttachmentDecryptor, AttachmentEncryptor, SealedAttachment};
pub use backup::SealedBackup;
pub use crypto::{KdfSettings, KDF_ITERATIONS, KDF_MEMORY_KIB, KDF_PARALLELISM};
pub use device::{DeviceKey, DeviceUnlock};
pub use error::{Error, InputError, Result};
pub use item::{AttachmentRef, CustomField, Item, ItemData, ItemDraft, LoginDraft, TotpDraft};
pub use limits::ATTACHMENT_CHUNK_SIZE;
pub use password::{generate_password, PasswordOptions};
pub use recovery::RecoveryKey;
pub use totp::{Hotp, Otp, Totp, TotpAlgorithm};
pub use vault::UnlockedVault;
pub use wire::{SealedItem, SealedVault};
