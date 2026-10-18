//! Local password strength. Nothing is sent off the machine.
//!
//! The score follows the same 0 to 4 scale Bitwarden shows for zxcvbn.

use zxcvbn::feedback::Warning;
use zxcvbn::zxcvbn;

/// A strength estimate. The score runs from 0 (worst) through 4 (best).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordStrength {
    /// 0 is very weak and 4 is strong.
    pub score: u8,
    /// Short Chinese guidance. Empty when there is nothing useful to say.
    pub warning: String,
}

/// Estimate how guessable a password is.
///
/// user_inputs are words the guesser should treat as known, such as the
/// login title or username. An empty password scores 0.
pub fn password_strength(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength {
            score: 0,
            warning: String::new(),
        };
    }
    let inputs: Vec<&str> = user_inputs
        .iter()
        .copied()
        .filter(|input| !input.is_empty())
        .collect();
    let estimate = zxcvbn(password, &inputs);
    PasswordStrength {
        score: u8::from(estimate.score()),
        warning: estimate
            .feedback()
            .and_then(|feedback| feedback.warning())
            .map(chinese_warning)
            .unwrap_or_default(),
    }
}

fn chinese_warning(warning: Warning) -> String {
    match warning {
        Warning::ThisIsATop10Password
        | Warning::ThisIsATop100Password
        | Warning::ThisIsACommonPassword => "这是常见密码",
        Warning::ThisIsSimilarToACommonlyUsedPassword => "这和常见密码太接近",
        Warning::AWordByItselfIsEasyToGuess => "单独一个单词很容易被猜到",
        Warning::NamesAndSurnamesByThemselvesAreEasyToGuess
        | Warning::CommonNamesAndSurnamesAreEasyToGuess => "姓名本身很容易被猜到",
        Warning::StraightRowsOfKeysAreEasyToGuess
        | Warning::ShortKeyboardPatternsAreEasyToGuess => "键盘上连成一排的字符很容易被猜到",
        Warning::RepeatsLikeAaaAreEasyToGuess
        | Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => "重复的片段很容易被猜到",
        Warning::SequencesLikeAbcAreEasyToGuess => "连续的字母或数字很容易被猜到",
        Warning::RecentYearsAreEasyToGuess => "近年的年份很容易被猜到",
        Warning::DatesAreOftenEasyToGuess => "日期很容易被猜到",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_common_password_scores_below_a_long_mixed_password() {
        let weak = password_strength("password", &[]);
        let strong = password_strength("r7#Qm2!vL9$eP4&cX8@nB6^wT3", &[]);
        assert!(weak.score <= 1);
        assert!(strong.score >= 3);
        assert!(weak.score < strong.score);
        assert!(!weak.warning.is_empty());
    }

    #[test]
    fn an_empty_password_scores_zero() {
        let strength = password_strength("", &["ada"]);
        assert_eq!(strength.score, 0);
        assert!(strength.warning.is_empty());
    }

    #[test]
    fn a_known_user_input_does_not_raise_the_score() {
        let plain = password_strength("ada-mailbox", &[]);
        let hinted = password_strength("ada-mailbox", &["ada-mailbox"]);
        assert!(hinted.score <= plain.score);
    }
}
