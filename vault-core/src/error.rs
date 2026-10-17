//! Typed failures. Hosts match variants; `Display` text is not a stable API.

use std::fmt;

/// Library result.
pub type Result<T> = std::result::Result<T, Error>;

/// A specific input failure. Numeric fields are public limits, never secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputError {
    /// The master password is empty.
    EmptyPassword,
    /// The item title has no non-whitespace characters.
    EmptyTitle,
    /// A login password name has no non-whitespace characters.
    EmptyPasswordName,
    /// The recovery key text is empty after removing whitespace.
    EmptyRecoveryKey,
    /// The recovery key is not unpadded base64url.
    InvalidRecoveryKeyEncoding,
    /// The decoded recovery key has the wrong size.
    InvalidRecoveryKeyLength {
        /// Required size in bytes.
        expected_bytes: usize,
    },
    /// The device key has the wrong size.
    InvalidDeviceKeyLength {
        /// Required size in bytes.
        expected_bytes: usize,
    },
    /// Creation settings are below the floor.
    WeakKdfParameters {
        /// Minimum Argon2 memory in KiB.
        min_memory_kib: u32,
        /// Minimum Argon2 iterations.
        min_iterations: u32,
    },
    /// An item body exceeds the plaintext ceiling.
    PayloadTooLarge {
        /// Maximum plaintext size in bytes.
        max_bytes: usize,
    },
    /// Generated password length is outside the supported range.
    InvalidPasswordLength {
        /// Minimum length.
        min: usize,
        /// Maximum length.
        max: usize,
    },
    /// Password generation was asked for an empty alphabet.
    NoCharacterGroups,
    /// The TOTP secret is not unpadded uppercase Base32.
    InvalidTotpSecretEncoding,
    /// The decoded TOTP secret is shorter than 128 bits.
    TotpSecretTooShort {
        /// Minimum secret size in bits.
        min_bits: usize,
    },
    /// TOTP digit count is outside 6..=8.
    InvalidTotpDigits {
        /// Minimum digits.
        min: u32,
        /// Maximum digits.
        max: u32,
    },
    /// TOTP period is zero or above the ceiling.
    InvalidTotpPeriod {
        /// Maximum period in seconds.
        max_seconds: u32,
    },
    /// A metadata list is longer than the per-item cap.
    TooManyMetadataEntries {
        /// Maximum entries.
        max_entries: usize,
    },
    /// An attachment reference is missing an id, revision, or file name.
    InvalidAttachmentReference,
    /// A folder id is nil.
    InvalidFolderId,
    /// The operation is not valid for a tombstone.
    DeletedItem,
    /// A login operation was used on another item kind.
    NotLoginItem,
    /// The operation needs an HOTP.
    NotHotp,
    /// A TOTP operation was used on another item kind.
    NotTotp,
    /// A folder operation was used on another item kind.
    NotFolder,
    /// A folder would contain itself through its parents.
    FolderCycle,
    /// A vault id is nil or does not match the open vault.
    InvalidVaultId,
    /// An item id is nil.
    InvalidItemId,
    /// A device id is nil.
    InvalidDeviceId,
    /// An attachment id is nil.
    InvalidAttachmentId,
    /// The vault already holds the maximum number of items.
    TooManyItems {
        /// Maximum item count.
        max_items: usize,
    },
    /// Two records use the same item id.
    DuplicateItemId,
    /// A revision is zero. The first stored revision is one.
    InvalidRevision,
    /// Bytes are truncated, have trailing data, or contain invalid text.
    MalformedEncoding,
    /// The next attachment chunk has the wrong size.
    InvalidAttachmentChunkLength {
        /// Required plaintext size of this chunk.
        expected_bytes: usize,
    },
    /// The attachment encryptor has already written its last chunk.
    AttachmentFinished,
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPassword => f.write_str("Master password must not be empty"),
            Self::EmptyTitle => f.write_str("Item title must not be empty"),
            Self::EmptyPasswordName => f.write_str("Login password name must not be empty"),
            Self::EmptyRecoveryKey => f.write_str("Recovery key must not be empty"),
            Self::InvalidRecoveryKeyEncoding => f.write_str("Recovery key must be valid unpadded base64url"),
            Self::InvalidRecoveryKeyLength { expected_bytes } => write!(f, "Recovery key must decode to {expected_bytes} bytes"),
            Self::InvalidDeviceKeyLength { expected_bytes } => write!(f, "Device key must contain {expected_bytes} bytes"),
            Self::WeakKdfParameters { min_memory_kib, min_iterations } => write!(f, "New KDF settings require at least {min_memory_kib} KiB of memory and {min_iterations} iterations"),
            Self::PayloadTooLarge { max_bytes } => write!(f, "Plaintext payload must not exceed {max_bytes} bytes"),
            Self::InvalidPasswordLength { min, max } => write!(f, "Generated password length must be between {min} and {max} characters"),
            Self::NoCharacterGroups => f.write_str("Select at least one password character group"),
            Self::InvalidTotpSecretEncoding => f.write_str("TOTP secret must be unpadded uppercase Base32"),
            Self::TotpSecretTooShort { min_bits } => write!(f, "TOTP secret must contain at least {min_bits} bits"),
            Self::InvalidTotpDigits { min, max } => write!(f, "TOTP digit count must be between {min} and {max}"),
            Self::InvalidTotpPeriod { max_seconds } => write!(f, "TOTP period must be between 1 and {max_seconds} seconds"),
            Self::TooManyMetadataEntries { max_entries } => write!(f, "Each item metadata collection must not exceed {max_entries} entries"),
            Self::InvalidAttachmentReference => f.write_str("Attachment reference requires a non-nil ID, a positive revision, and a non-empty filename"),
            Self::InvalidFolderId => f.write_str("Folder ID must not be nil"),
            Self::DeletedItem => f.write_str("Operation is not allowed on a deleted item"),
            Self::NotLoginItem => f.write_str("Item must be a login item"),
            Self::NotHotp => f.write_str("Item must contain an HOTP"),
            Self::NotTotp => f.write_str("Item must be a standalone TOTP item"),
            Self::NotFolder => f.write_str("Item must be a folder"),
            Self::FolderCycle => f.write_str("Folder cannot contain itself"),
            Self::InvalidVaultId => f.write_str("Vault ID must not be nil"),
            Self::InvalidItemId => f.write_str("Item ID must not be nil"),
            Self::InvalidDeviceId => f.write_str("Device ID must not be nil"),
            Self::InvalidAttachmentId => f.write_str("Attachment ID must not be nil"),
            Self::TooManyItems { max_items } => write!(f, "Vault must not contain more than {max_items} items"),
            Self::DuplicateItemId => f.write_str("Duplicate item ID"),
            Self::InvalidRevision => f.write_str("Revision must be at least 1"),
            Self::MalformedEncoding => f.write_str("Record encoding is truncated, padded, or not valid UTF-8"),
            Self::InvalidAttachmentChunkLength { expected_bytes } => write!(f, "Next attachment chunk must contain {expected_bytes} bytes"),
            Self::AttachmentFinished => f.write_str("Attachment encryption is already complete"),
        }
    }
}

impl std::error::Error for InputError {}

/// Failure category. Match with a wildcard; variants may be added.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input validation failed.
    InvalidInput(InputError),
    /// The password, recovery key, or key wrap did not authenticate.
    /// Those causes are intentionally indistinguishable.
    UnlockFailed,
    /// Ciphertext or its associated data failed verification.
    Integrity,
    /// The item is not in this vault.
    NotFound,
    /// This vault has no recovery wrap.
    NoRecoveryKey,
    /// The version, algorithm, or KDF parameters are not supported.
    UnsupportedFormat,
    /// An internal invariant failed.
    Internal,
    /// The operating system random source failed.
    RandomUnavailable,
    /// The revision does not match the record currently stored.
    Conflict,
    /// A byte or memory ceiling was exceeded.
    LimitExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(reason) => write!(f, "Invalid input: {reason}"),
            Self::UnlockFailed => f.write_str("Unable to unlock vault"),
            Self::Integrity => f.write_str("Integrity verification failed"),
            Self::NotFound => f.write_str("Item not found"),
            Self::NoRecoveryKey => f.write_str("Vault has no recovery key"),
            Self::UnsupportedFormat => f.write_str("Unsupported vault format or parameters"),
            Self::Internal => f.write_str("Internal error"),
            Self::RandomUnavailable => f.write_str("Secure random source unavailable"),
            Self::Conflict => f.write_str("Item revision conflict"),
            Self::LimitExceeded => f.write_str("Resource limit exceeded"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInput(reason) => Some(reason),
            _ => None,
        }
    }
}
