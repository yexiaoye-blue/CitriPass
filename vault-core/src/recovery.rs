//! Recovery key: a second 32-byte secret that wraps the same vault key.
//! The handwritten form is unpadded base64url. It is not part of the vault file.

use crate::crypto::{self, KEY_LEN};
use crate::{Error, InputError, Result};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Offline recovery secret. Cloning is intentionally unavailable, and Debug is redacted.
pub struct RecoveryKey(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKey {
    /// Draw 256 bits from the operating system CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(crypto::random_array()?)))
    }

    /// Groups of four base64url characters. Dash and underscore are data and are kept.
    pub fn to_text(&self) -> Zeroizing<String> {
        use base64::Engine;
        let encoded = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.as_ref()),
        );
        let mut text = Zeroizing::new(String::with_capacity(encoded.len() + encoded.len() / 4));
        for (index, group) in encoded.as_bytes().chunks(4).enumerate() {
            if index > 0 {
                text.push(' ');
            }
            text.extend(group.iter().copied().map(char::from));
        }
        text
    }

    /// Parse handwritten text. Whitespace is ignored; every other character is data.
    pub fn from_text(text: &str) -> Result<Self> {
        use base64::Engine;
        if text.len() > 256 {
            return Err(Error::LimitExceeded);
        }
        let compact: String = text
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if compact.is_empty() {
            return Err(Error::InvalidInput(InputError::EmptyRecoveryKey));
        }
        let mut bytes = Zeroizing::new(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(compact.as_bytes())
                .map_err(|_| Error::InvalidInput(InputError::InvalidRecoveryKeyEncoding))?,
        );
        if bytes.len() != KEY_LEN {
            bytes.zeroize();
            return Err(Error::InvalidInput(InputError::InvalidRecoveryKeyLength {
                expected_bytes: KEY_LEN,
            }));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        bytes.zeroize();
        Ok(Self(Zeroizing::new(key)))
    }
}

impl AsRef<[u8]> for RecoveryKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(***)")
    }
}
