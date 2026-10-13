//! RFC 6238. The caller supplies Unix time; this crate does not read a clock.

use crate::{Error, InputError, Result};
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HMAC digest used by a TOTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1.
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// TOTP parameters and secret. The secret is wiped on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Totp {
    /// Unpadded uppercase Base32 secret.
    pub secret: String,
    /// HMAC algorithm.
    pub algorithm: TotpAlgorithm,
    /// Displayed digits, 6 through 8.
    pub digits: u32,
    /// Step size in seconds, 1 through 300.
    pub period: u32,
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Totp(***)")
    }
}

impl Totp {
    /// SHA-1, 6 digits, 30 seconds. Validation happens at use.
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
        }
    }

    /// Check encoding, secret size, digits, and period.
    pub fn validate(&self) -> Result<()> {
        self.validate_parameters()?;
        self.key()?;
        Ok(())
    }

    /// Code for the given Unix second.
    pub fn code_at(&self, unix_seconds: u64) -> Result<Zeroizing<String>> {
        self.validate_parameters()?;
        let key = self.key()?;
        let counter = (unix_seconds / u64::from(self.period)).to_be_bytes();
        macro_rules! digest {
            ($hash:ty) => {{
                let mut mac = Hmac::<$hash>::new_from_slice(&key).map_err(|_| Error::Internal)?;
                mac.update(&counter);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }};
        }
        let digest = match self.algorithm {
            TotpAlgorithm::Sha1 => digest!(sha1::Sha1),
            TotpAlgorithm::Sha256 => digest!(sha2::Sha256),
            TotpAlgorithm::Sha512 => digest!(sha2::Sha512),
        };
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let binary = u32::from_be_bytes(
            digest[offset..offset + 4]
                .try_into()
                .map_err(|_| Error::Internal)?,
        ) & 0x7fff_ffff;
        let modulus = 10u32.pow(self.digits);
        Ok(Zeroizing::new(format!(
            "{:0width$}",
            binary % modulus,
            width = self.digits as usize
        )))
    }

    fn validate_parameters(&self) -> Result<()> {
        if !(6..=8).contains(&self.digits) {
            return Err(Error::InvalidInput(InputError::InvalidTotpDigits {
                min: 6,
                max: 8,
            }));
        }
        if self.period == 0 || self.period > 300 {
            return Err(Error::InvalidInput(InputError::InvalidTotpPeriod {
                max_seconds: 300,
            }));
        }
        Ok(())
    }

    fn key(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.secret.len() > 1024 {
            return Err(Error::LimitExceeded);
        }
        let bytes = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(self.secret.as_bytes())
                .map_err(|_| Error::InvalidInput(InputError::InvalidTotpSecretEncoding))?,
        );
        if bytes.len() < 16 {
            return Err(Error::InvalidInput(InputError::TotpSecretTooShort {
                min_bits: 128,
            }));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_at_59_seconds() {
        let mut totp = Totp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        totp.digits = 8;
        assert_eq!(totp.code_at(59).unwrap().as_str(), "94287082");
    }
}
