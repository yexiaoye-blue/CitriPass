//! RFC 6238 TOTP and RFC 4226 HOTP. The caller supplies the time or counter.

use crate::{Error, InputError, Result};
use hmac::{Hmac, Mac};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HMAC digest used by a TOTP or HOTP.
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

/// HOTP parameters and secret. The secret is wiped on drop.
///
/// `counter` is the next moving factor. [`Hotp::next_code`] returns the code
/// for the current counter and then advances it. The new counter must be stored
/// before the code is shown again, or the same code will be produced twice.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Hotp {
    /// Unpadded uppercase Base32 secret.
    pub secret: String,
    /// HMAC algorithm.
    pub algorithm: TotpAlgorithm,
    /// Displayed digits, 6 through 8.
    pub digits: u32,
    /// Next counter. It is not a secret.
    #[zeroize(skip)]
    pub counter: u64,
}

/// One-time password stored with an item.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Otp {
    /// Time-based code.
    Totp(Totp),
    /// Counter-based code.
    Hotp(Hotp),
}

impl std::fmt::Debug for Totp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Totp(***)")
    }
}

impl std::fmt::Debug for Hotp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hotp(***)")
    }
}

impl std::fmt::Debug for Otp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Otp(***)")
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
        validate_digits(self.digits)?;
        if self.period == 0 || self.period > 300 {
            return Err(Error::InvalidInput(InputError::InvalidTotpPeriod {
                max_seconds: 300,
            }));
        }
        decode_secret(&self.secret)?;
        Ok(())
    }

    /// Code for the given Unix second.
    pub fn code_at(&self, unix_seconds: u64) -> Result<Zeroizing<String>> {
        self.validate()?;
        let key = decode_secret(&self.secret)?;
        otp_code(
            self.algorithm,
            &key,
            unix_seconds / u64::from(self.period),
            self.digits,
        )
    }
}

impl Hotp {
    /// SHA-1 and 6 digits. Validation happens at use.
    pub fn new(secret: impl Into<String>, counter: u64) -> Self {
        Self {
            secret: secret.into(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            counter,
        }
    }

    /// Check encoding, secret size, and digits.
    pub fn validate(&self) -> Result<()> {
        validate_digits(self.digits)?;
        decode_secret(&self.secret)?;
        Ok(())
    }

    /// Code for an explicit counter. This does not change [`Hotp::counter`].
    pub fn code_at(&self, counter: u64) -> Result<Zeroizing<String>> {
        self.validate()?;
        let key = decode_secret(&self.secret)?;
        otp_code(self.algorithm, &key, counter, self.digits)
    }

    /// Code for the current counter, then advance the counter by one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LimitExceeded`] when the counter is already `u64::MAX`.
    /// The counter is left unchanged when code generation fails.
    pub fn next_code(&mut self) -> Result<Zeroizing<String>> {
        if self.counter == u64::MAX {
            return Err(Error::LimitExceeded);
        }
        let code = self.code_at(self.counter)?;
        self.counter += 1;
        Ok(code)
    }
}

impl Otp {
    /// Check the selected password's parameters.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Totp(totp) => totp.validate(),
            Self::Hotp(hotp) => hotp.validate(),
        }
    }
}

fn validate_digits(digits: u32) -> Result<()> {
    if !(6..=8).contains(&digits) {
        return Err(Error::InvalidInput(InputError::InvalidTotpDigits {
            min: 6,
            max: 8,
        }));
    }
    Ok(())
}

fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    if secret.len() > 1024 {
        return Err(Error::LimitExceeded);
    }
    let bytes = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(secret.as_bytes())
            .map_err(|_| Error::InvalidInput(InputError::InvalidTotpSecretEncoding))?,
    );
    if bytes.len() < 16 {
        return Err(Error::InvalidInput(InputError::TotpSecretTooShort {
            min_bits: 128,
        }));
    }
    Ok(bytes)
}

fn otp_code(
    algorithm: TotpAlgorithm,
    key: &[u8],
    counter: u64,
    digits: u32,
) -> Result<Zeroizing<String>> {
    let counter = counter.to_be_bytes();
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(key).map_err(|_| Error::Internal)?;
            mac.update(&counter);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }};
    }
    let digest = match algorithm {
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
    let modulus = 10u32.pow(digits);
    Ok(Zeroizing::new(format!(
        "{:0width$}",
        binary % modulus,
        width = digits as usize
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_sha1_at_59_seconds() {
        let mut totp = Totp::new(SECRET);
        totp.digits = 8;
        assert_eq!(totp.code_at(59).unwrap().as_str(), "94287082");
    }

    #[test]
    fn rfc6238_sha256_and_sha512_at_59_seconds() {
        let mut sha256 = Totp::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA");
        sha256.algorithm = TotpAlgorithm::Sha256;
        sha256.digits = 8;
        assert_eq!(sha256.code_at(59).unwrap().as_str(), "46119246");

        let mut sha512 = Totp::new(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
        );
        sha512.algorithm = TotpAlgorithm::Sha512;
        sha512.digits = 8;
        assert_eq!(sha512.code_at(59).unwrap().as_str(), "90693936");
    }

    #[test]
    fn rfc4226_sha1_advances_the_counter() {
        let mut hotp = Hotp::new(SECRET, 0);
        assert_eq!(hotp.next_code().unwrap().as_str(), "755224");
        assert_eq!(hotp.counter, 1);
        assert_eq!(hotp.code_at(1).unwrap().as_str(), "287082");
        assert_eq!(hotp.counter, 1);
    }

    #[test]
    fn hotp_rejects_a_saturated_counter_without_moving_it() {
        let mut hotp = Hotp::new(SECRET, u64::MAX);
        assert!(matches!(hotp.next_code(), Err(Error::LimitExceeded)));
        assert_eq!(hotp.counter, u64::MAX);
    }

    #[test]
    fn hotp_advances_to_the_saturated_counter_then_stops() {
        let mut hotp = Hotp::new(SECRET, u64::MAX - 1);
        hotp.next_code().unwrap();
        assert_eq!(hotp.counter, u64::MAX);
        assert!(matches!(hotp.next_code(), Err(Error::LimitExceeded)));
        assert_eq!(hotp.counter, u64::MAX);
    }
}
