//! Uniform sampling. Rejection removes modulo bias and enforces character groups.

use crate::{Error, InputError, Result};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^*_-";
const AMBIGUOUS: &[u8] = b"IOilo01";
const MIN_PASSPHRASE_WORDS: usize = 3;
const MAX_PASSPHRASE_WORDS: usize = 20;
const MAX_SEPARATOR_CHARS: usize = 16;

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
    /// Drop the ambiguous characters in I, O, i, l, o, 0, and 1.
    pub avoid_ambiguous: bool,
    /// Minimum digits. A selected digit group still contributes at least one.
    pub min_digits: usize,
    /// Minimum symbols. A selected symbol group still contributes at least one.
    pub min_symbols: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 24,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
            min_digits: 1,
            min_symbols: 1,
        }
    }
}

/// Passphrase shape. Words come from the EFF large wordlist.
#[derive(Clone, Debug)]
pub struct PassphraseOptions {
    /// Number of words, 3 through 20. The default is 6.
    pub words: usize,
    /// Text placed between words. Empty is allowed.
    pub separator: String,
    /// Capitalize the first letter of each word.
    pub capitalize: bool,
    /// Append one digit to a randomly chosen word.
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".to_string(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Generate a password. The returned buffer is wiped on drop.
///
/// Sampling uses the operating-system CSPRNG. Every selected character group
/// appears at least once, and digit or symbol minimums can require more.
pub fn generate_password(options: &PasswordOptions) -> Result<Zeroizing<String>> {
    generate_with_rng(options, &mut rand::rngs::OsRng)
}

/// Generate a passphrase. The returned buffer is wiped on drop.
pub fn generate_passphrase(options: &PassphraseOptions) -> Result<Zeroizing<String>> {
    passphrase_with_rng(options, &mut rand::rngs::OsRng)
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
    let groups = selected_groups(options)?;
    if groups.iter().all(|group| group.is_empty()) {
        return Err(Error::InvalidInput(InputError::NoCharacterGroups));
    }
    let minimums = minimum_counts(options)?;
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
        if meets_minimums(&bytes, &groups, &minimums) {
            return Ok(Zeroizing::new(
                String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| Error::Internal)?,
            ));
        }
    }
}

fn passphrase_with_rng<R: RngCore + CryptoRng>(
    options: &PassphraseOptions,
    rng: &mut R,
) -> Result<Zeroizing<String>> {
    if !(MIN_PASSPHRASE_WORDS..=MAX_PASSPHRASE_WORDS).contains(&options.words) {
        return Err(Error::InvalidInput(
            InputError::InvalidPassphraseWordCount {
                min: MIN_PASSPHRASE_WORDS,
                max: MAX_PASSPHRASE_WORDS,
            },
        ));
    }
    if options.separator.chars().count() > MAX_SEPARATOR_CHARS
        || options.separator.chars().any(char::is_control)
    {
        return Err(Error::InvalidInput(InputError::InvalidPassphraseSeparator));
    }
    let words = wordlist();
    let mut chosen = Vec::with_capacity(options.words);
    for _ in 0..options.words {
        let index = sample_index(rng, words.len())?;
        chosen.push(words[index].to_string());
    }
    if options.capitalize {
        for word in &mut chosen {
            let mut characters = word.chars();
            let Some(first) = characters.next() else {
                continue;
            };
            *word = first.to_uppercase().collect::<String>() + characters.as_str();
        }
    }
    if options.include_number {
        let index = sample_index(rng, chosen.len())?;
        let digit = sample_index(rng, 10)?;
        chosen[index].push(char::from_digit(digit as u32, 10).ok_or(Error::Internal)?);
    }
    Ok(Zeroizing::new(chosen.join(&options.separator)))
}

fn selected_groups(options: &PasswordOptions) -> Result<Vec<Vec<u8>>> {
    let mut groups = Vec::new();
    for (enabled, alphabet) in [
        (options.lowercase, LOWER),
        (options.uppercase, UPPER),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ] {
        if !enabled {
            groups.push(Vec::new());
            continue;
        }
        let group = filter_alphabet(alphabet, options.avoid_ambiguous);
        if group.is_empty() {
            return Err(Error::InvalidInput(InputError::EmptyCharacterGroup));
        }
        groups.push(group);
    }
    Ok(groups)
}

fn filter_alphabet(alphabet: &[u8], avoid_ambiguous: bool) -> Vec<u8> {
    alphabet
        .iter()
        .copied()
        .filter(|byte| !avoid_ambiguous || !AMBIGUOUS.contains(byte))
        .collect()
}

fn minimum_counts(options: &PasswordOptions) -> Result<[usize; 4]> {
    let minimums = [
        usize::from(options.lowercase),
        usize::from(options.uppercase),
        if options.digits {
            options.min_digits.max(1)
        } else {
            0
        },
        if options.symbols {
            options.min_symbols.max(1)
        } else {
            0
        },
    ];
    let required = minimums
        .iter()
        .try_fold(0usize, |total, count| total.checked_add(*count));
    if required.is_none_or(|total| total > options.length) {
        return Err(Error::InvalidInput(InputError::InvalidPasswordConstraints));
    }
    Ok(minimums)
}

fn meets_minimums(bytes: &[u8], groups: &[Vec<u8>], minimums: &[usize; 4]) -> bool {
    groups.iter().zip(minimums).all(|(group, minimum)| {
        group.is_empty() || bytes.iter().filter(|byte| group.contains(byte)).count() >= *minimum
    })
}

fn sample_index<R: RngCore + CryptoRng>(rng: &mut R, upper: usize) -> Result<usize> {
    let upper = u32::try_from(upper).map_err(|_| Error::Internal)?;
    if upper == 0 {
        return Err(Error::Internal);
    }
    let zone = u32::MAX - (u32::MAX % upper);
    loop {
        let mut bytes = [0u8; 4];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| Error::RandomUnavailable)?;
        let value = u32::from_ne_bytes(bytes);
        if value < zone {
            return Ok((value % upper) as usize);
        }
    }
}

fn wordlist() -> &'static [&'static str] {
    use std::sync::OnceLock;
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS
        .get_or_init(|| {
            include_str!("../assets/eff_large_wordlist.txt")
                .lines()
                .filter_map(|line| line.split('\t').nth(1))
                .collect()
        })
        .as_slice()
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
            avoid_ambiguous: false,
            min_digits: 0,
            min_symbols: 0,
        };
        let password = generate_with_rng(&options, &mut rng).unwrap();
        assert_eq!(password.as_str(), "abcdefghijklmnopqrstuvwxyz");
        assert_eq!(rng.calls, 1);
    }

    #[test]
    fn ambiguous_characters_stay_out_and_minimums_are_present() {
        let options = PasswordOptions {
            length: 64,
            avoid_ambiguous: true,
            min_digits: 4,
            min_symbols: 2,
            ..PasswordOptions::default()
        };
        let password = generate_password(&options).unwrap();
        assert!(password.bytes().all(|byte| !AMBIGUOUS.contains(&byte)));
        assert!(
            password
                .bytes()
                .filter(|byte| byte.is_ascii_digit())
                .count()
                >= 4
        );
        assert!(
            password
                .bytes()
                .filter(|byte| SYMBOLS.contains(byte) && !AMBIGUOUS.contains(byte))
                .count()
                >= 2
        );
    }

    #[test]
    fn symbols_use_the_fixed_special_set() {
        let options = PasswordOptions {
            length: 24,
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: true,
            min_digits: 0,
            ..PasswordOptions::default()
        };
        let password = generate_password(&options).unwrap();
        assert!(password.bytes().all(|byte| SYMBOLS.contains(&byte)));
        assert_eq!(SYMBOLS, b"!@#$%^*_-");
        assert_eq!(AMBIGUOUS, b"IOilo01");
    }

    #[test]
    fn impossible_character_minimums_are_rejected() {
        let options = PasswordOptions {
            length: 8,
            min_digits: 6,
            min_symbols: 6,
            ..PasswordOptions::default()
        };
        assert_eq!(
            generate_password(&options).unwrap_err(),
            Error::InvalidInput(InputError::InvalidPasswordConstraints)
        );
    }

    #[test]
    fn no_character_group_is_rejected() {
        let options = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert_eq!(
            generate_password(&options).unwrap_err(),
            Error::InvalidInput(InputError::NoCharacterGroups)
        );
    }

    #[test]
    fn passphrase_uses_six_eff_words_by_default() {
        assert_eq!(wordlist().len(), 7776);
        assert_eq!(wordlist()[0], "abacus");
        assert!(wordlist().iter().all(|word| {
            word.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        }));
        let phrase = generate_passphrase(&PassphraseOptions {
            separator: " ".to_string(),
            ..PassphraseOptions::default()
        })
        .unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|word| wordlist().contains(word)));
    }

    #[test]
    fn passphrase_can_capitalize_and_add_one_number() {
        let phrase = generate_passphrase(&PassphraseOptions {
            words: 4,
            separator: " ".to_string(),
            capitalize: true,
            include_number: true,
        })
        .unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(words.len(), 4);
        assert!(words
            .iter()
            .all(|word| word.chars().next().unwrap().is_ascii_uppercase()));
        let numbered = words
            .iter()
            .filter(|word| word.chars().last().unwrap().is_ascii_digit())
            .count();
        assert_eq!(numbered, 1);
    }

    #[test]
    fn passphrase_rejects_a_control_separator() {
        let error = generate_passphrase(&PassphraseOptions {
            separator: "\n".to_string(),
            ..PassphraseOptions::default()
        })
        .unwrap_err();
        assert_eq!(
            error,
            Error::InvalidInput(InputError::InvalidPassphraseSeparator)
        );
    }
}
