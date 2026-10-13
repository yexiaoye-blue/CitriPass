//! Uniform sampling. Rejection removes modulo bias and enforces character groups.

use crate::{Error, InputError, Result};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Password length and the character groups that must each appear once.
#[derive(Clone, Debug)]
pub struct PasswordOptions {
    /// ASCII length, 8 through 1024.
    pub length: usize,
    /// Require a lowercase ASCII letter.
    pub lowercase: bool,
    /// Require an uppercase ASCII letter.
    pub uppercase: bool,
    /// Require an ASCII digit.
    pub digits: bool,
    /// Require a symbol from the supported alphabet.
    pub symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a password. The returned buffer is wiped on drop.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    generate_with_rng(options, &mut rand::rngs::OsRng)
}

pub(crate) fn generate_with_rng<R: RngCore + CryptoRng>(
    options: &PasswordOptions,
    rng: &mut R,
) -> Result<Zeroizing<String>> {
    if !(8..=1024).contains(&options.length) {
        return Err(Error::InvalidInput(InputError::InvalidPasswordLength {
            min: 8,
            max: 1024,
        }));
    }
    let groups: Vec<&[u8]> = [
        (options.lowercase, b"abcdefghijklmnopqrstuvwxyz".as_slice()),
        (options.uppercase, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
        (options.digits, b"0123456789".as_slice()),
        (options.symbols, b"!@#$%^&*()-_=+[]{}:,.?".as_slice()),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, alphabet)| alphabet)
    .collect();
    if groups.is_empty() {
        return Err(Error::InvalidInput(InputError::NoCharacterGroups));
    }
    let alphabet: Vec<u8> = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    let bound = 256 - (256 % alphabet.len());
    let mut random = Zeroizing::new([0u8; 256]);
    let mut cursor = random.len();
    loop {
        let mut bytes = Zeroizing::new(Vec::with_capacity(options.length));
        while bytes.len() < options.length {
            if cursor == random.len() {
                rng.try_fill_bytes(random.as_mut())
                    .map_err(|_| Error::RandomUnavailable)?;
                cursor = 0;
            }
            let sample = usize::from(random[cursor]);
            cursor += 1;
            if sample < bound {
                bytes.push(alphabet[sample % alphabet.len()]);
            }
        }
        if groups
            .iter()
            .all(|group| bytes.iter().any(|byte| group.contains(byte)))
        {
            return Ok(Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| Error::Internal)?,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng {
        next: u8,
        calls: usize,
        fail_after: usize,
    }

    impl CryptoRng for TestRng {}
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest).unwrap();
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            if self.calls == self.fail_after {
                return Err(rand::Error::from(
                    std::num::NonZeroU32::new(rand::Error::CUSTOM_START).unwrap(),
                ));
            }
            self.calls += 1;
            for byte in dest {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn rejection_sampling_discards_the_biased_tail() {
        let mut rng = TestRng {
            next: 250,
            calls: 0,
            fail_after: usize::MAX,
        };
        let options = PasswordOptions {
            length: 26,
            lowercase: true,
            uppercase: false,
            digits: false,
            symbols: false,
        };
        let password = generate_with_rng(&options, &mut rng).unwrap();
        assert_eq!(password.as_str(), "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(rng.calls, 1);
    }
}
