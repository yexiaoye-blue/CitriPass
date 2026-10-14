//! KeePass one-time passwords mapped onto [`vault_core::Otp`].
//!
//! KeePassXC and the `otpauth` URL default to 6 digits. The `keepass` crate's
//! optional parser defaults to 8, which would mint different codes, so this
//! module reads the fields itself.

use data_encoding::{BASE32_NOPAD, BASE64, BASE64_NOPAD, HEXLOWER};
use keepass::db::{fields, Entry};
use vault_core::{Hotp, Otp, Totp, TotpAlgorithm};

pub(crate) enum OtpDecision {
    Absent,
    Value(Otp),
    Skipped { detail: String },
}

pub(crate) fn from_entry(entry: &Entry) -> OtpDecision {
    if let Some(raw) = nonempty(entry, fields::OTP) {
        return match parse_otpauth(raw) {
            Ok(otp) => OtpDecision::Value(otp),
            Err(detail) => OtpDecision::Skipped { detail },
        };
    }
    if let Some(seed) = nonempty(entry, "TOTP Seed") {
        return totp_decision(parse_seed(seed, entry.get("TOTP Settings")));
    }
    if let Some(seed) =
        nonempty(entry, "TimeOtp-Secret-Base32").or_else(|| nonempty(entry, "TimeOtp-Secret"))
    {
        return totp_decision(parse_timeotp(entry, seed));
    }
    hmac_from_entry(entry).unwrap_or(OtpDecision::Absent)
}

fn totp_decision(result: Result<Totp, String>) -> OtpDecision {
    match result {
        Ok(totp) => OtpDecision::Value(Otp::Totp(totp)),
        Err(detail) => OtpDecision::Skipped { detail },
    }
}

fn nonempty<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    entry
        .get(name)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn parse_otpauth(raw: &str) -> Result<Otp, String> {
    let rest = raw
        .trim()
        .strip_prefix("otpauth://")
        .ok_or_else(|| "one-time password value is not an otpauth URL".to_string())?;
    let (path, query) = rest
        .split_once('?')
        .ok_or_else(|| "otpauth URL has no parameters".to_string())?;
    let kind = path.split('/').next().unwrap_or(path);
    let hotp = if kind.eq_ignore_ascii_case("totp") {
        false
    } else if kind.eq_ignore_ascii_case("hotp") {
        true
    } else {
        return Err("only TOTP and HOTP otpauth URLs are imported".to_string());
    };

    let mut secret = None;
    let mut period = 30u32;
    let mut digits = 6u32;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut counter = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(value),
            "period" if !hotp => period = parse_u32(&value, "TOTP period")?,
            "digits" => digits = parse_u32(&value, "one-time password digit count")?,
            "algorithm" => algorithm = parse_algorithm(&value)?,
            "counter" => counter = Some(parse_u64(&value, "HOTP counter")?),
            _ => {}
        }
    }
    let secret = secret.ok_or_else(|| "otpauth URL has no secret".to_string())?;
    if hotp {
        let counter = counter.ok_or_else(|| "otpauth HOTP URL has no counter".to_string())?;
        return Ok(Otp::Hotp(build_hotp(&secret, counter, digits, algorithm)?));
    }
    Ok(Otp::Totp(build_totp(&secret, period, digits, algorithm)?))
}

fn parse_seed(seed: &str, settings: Option<&str>) -> Result<Totp, String> {
    let (period, digits, algorithm) =
        match settings.map(str::trim).filter(|value| !value.is_empty()) {
            None => (30, 6, TotpAlgorithm::Sha1),
            Some(value) => parse_settings(value)?,
        };
    build_totp(seed, period, digits, algorithm)
}

fn parse_timeotp(entry: &Entry, seed: &str) -> Result<Totp, String> {
    let period = match nonempty(entry, "TimeOtp-Period") {
        None => 30,
        Some(value) => parse_u32(value, "TOTP period")?,
    };
    let digits =
        match nonempty(entry, "TimeOtp-Length").or_else(|| nonempty(entry, "TimeOtp-Digits")) {
            None => 6,
            Some(value) => parse_u32(value, "TOTP digit count")?,
        };
    let algorithm = match nonempty(entry, "TimeOtp-Algorithm") {
        None => TotpAlgorithm::Sha1,
        Some(value) => parse_algorithm(value)?,
    };
    build_totp(seed, period, digits, algorithm)
}

fn hmac_from_entry(entry: &Entry) -> Option<OtpDecision> {
    let encoded = if let Some(value) = nonempty(entry, "HmacOtp-Secret-Base32") {
        normalize_secret(value, "HOTP")
    } else if let Some(value) = nonempty(entry, "HmacOtp-Secret-Base64") {
        secret_from_base64(value)
    } else if let Some(value) = nonempty(entry, "HmacOtp-Secret-Hex") {
        secret_from_hex(value)
    } else {
        // KeePass stores the raw UTF-8 secret in this field, not Base32.
        let value = nonempty(entry, "HmacOtp-Secret")?;
        secret_from_raw(value)
    };
    Some(match finish_hotp(entry, encoded) {
        Ok(hotp) => OtpDecision::Value(Otp::Hotp(hotp)),
        Err(detail) => OtpDecision::Skipped { detail },
    })
}

fn finish_hotp(entry: &Entry, secret: Result<String, String>) -> Result<Hotp, String> {
    let secret = secret?;
    let counter = match nonempty(entry, "HmacOtp-Counter") {
        None => 0,
        Some(value) => parse_u64(value, "HOTP counter")?,
    };
    let digits =
        match nonempty(entry, "HmacOtp-Length").or_else(|| nonempty(entry, "HmacOtp-Digits")) {
            None => 6,
            Some(value) => parse_u32(value, "HOTP digit count")?,
        };
    let algorithm = match nonempty(entry, "HmacOtp-Algorithm") {
        None => TotpAlgorithm::Sha1,
        Some(value) => parse_algorithm(value)?,
    };
    hotp_from_canonical(secret, counter, digits, algorithm)
}

fn parse_settings(value: &str) -> Result<(u32, u32, TotpAlgorithm), String> {
    let mut parts = value.split(';');
    let period = parse_u32(parts.next().unwrap_or("").trim(), "TOTP period")?;
    let digits = parse_u32(parts.next().unwrap_or("").trim(), "TOTP digit count")?;
    let algorithm = match parts.next().map(str::trim).filter(|part| !part.is_empty()) {
        None => TotpAlgorithm::Sha1,
        Some(name) => parse_algorithm(name)?,
    };
    if parts.next().is_some() {
        return Err("TOTP settings have too many fields".to_string());
    }
    Ok((period, digits, algorithm))
}

fn parse_algorithm(value: &str) -> Result<TotpAlgorithm, String> {
    let name: String = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_uppercase())
        .collect();
    match name.as_str() {
        "SHA1" | "HMACSHA1" => Ok(TotpAlgorithm::Sha1),
        "SHA256" | "HMACSHA256" => Ok(TotpAlgorithm::Sha256),
        "SHA512" | "HMACSHA512" => Ok(TotpAlgorithm::Sha512),
        _ => Err("one-time password algorithm is not supported".to_string()),
    }
}

fn parse_u32(value: &str, label: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("{label} is not a whole number"))
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{label} is not a whole number"))
}

fn build_totp(
    secret: &str,
    period: u32,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<Totp, String> {
    if !(6..=8).contains(&digits) {
        return Err("TOTP digit count is outside 6..=8".to_string());
    }
    if period == 0 || period > 300 {
        return Err("TOTP period is outside 1..=300 seconds".to_string());
    }
    let mut totp = Totp::new(normalize_secret(secret, "TOTP")?);
    totp.period = period;
    totp.digits = digits;
    totp.algorithm = algorithm;
    Ok(totp)
}

fn build_hotp(
    secret: &str,
    counter: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<Hotp, String> {
    hotp_from_canonical(
        normalize_secret(secret, "HOTP")?,
        counter,
        digits,
        algorithm,
    )
}

fn hotp_from_canonical(
    secret: String,
    counter: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<Hotp, String> {
    if !(6..=8).contains(&digits) {
        return Err("HOTP digit count is outside 6..=8".to_string());
    }
    let mut hotp = Hotp::new(secret, counter);
    hotp.digits = digits;
    hotp.algorithm = algorithm;
    Ok(hotp)
}

fn normalize_secret(raw: &str, kind: &str) -> Result<String, String> {
    let compact: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if compact.is_empty() {
        return Err(format!("{kind} secret is empty"));
    }
    if !compact.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
        return Err(format!("{kind} secret is not base32"));
    }
    let bytes = BASE32_NOPAD
        .decode(compact.as_bytes())
        .map_err(|_| format!("{kind} secret is not base32"))?;
    canonical_bytes(&bytes, kind)
}

fn secret_from_base64(raw: &str) -> Result<String, String> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = BASE64
        .decode(compact.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(compact.as_bytes()))
        .map_err(|_| "HOTP secret is not base64".to_string())?;
    canonical_bytes(&bytes, "HOTP")
}

fn secret_from_hex(raw: &str) -> Result<String, String> {
    let compact: String = raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let bytes = HEXLOWER
        .decode(compact.as_bytes())
        .map_err(|_| "HOTP secret is not hex".to_string())?;
    canonical_bytes(&bytes, "HOTP")
}

fn secret_from_raw(raw: &str) -> Result<String, String> {
    canonical_bytes(raw.as_bytes(), "HOTP")
}

fn canonical_bytes(bytes: &[u8], kind: &str) -> Result<String, String> {
    if bytes.is_empty() {
        return Err(format!("{kind} secret is empty"));
    }
    if bytes.len() < 16 {
        return Err(format!("{kind} secret is shorter than 128 bits"));
    }
    Ok(BASE32_NOPAD.encode(bytes))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_digit(bytes[index + 1]), hex_digit(bytes[index + 2]))
            {
                let value = (high << 4) | low;
                out.push(value);
                index += 3;
                continue;
            }
        }
        if bytes[index] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[index]);
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn entry_with(fill: impl FnOnce(&mut keepass::db::EntryMut<'_>)) -> keepass::Database {
        let mut db = Database::new();
        fill(&mut db.root_mut().add_entry());
        db
    }

    #[test]
    fn otpauth_defaults_to_six_digits_and_canonical_base32() {
        let db = entry_with(|entry| {
            entry.set_unprotected(
                fields::OTP,
                format!(
                    "otpauth://totp/Example:ada?secret={secret}&algorithm=SHA256&digits=8&period=45",
                    secret = SECRET.to_lowercase()
                ),
            );
        });
        let OtpDecision::Value(Otp::Totp(ref totp)) =
            from_entry(&db.root().entries().next().unwrap())
        else {
            panic!("expected a totp");
        };
        assert_eq!(totp.secret, SECRET);
        assert_eq!(totp.digits, 8);
        assert_eq!(totp.period, 45);
        assert_eq!(totp.algorithm, TotpAlgorithm::Sha256);
    }

    #[test]
    fn short_secret_is_skipped_without_echoing_it() {
        let db = entry_with(|entry| {
            entry.set_unprotected(fields::OTP, "otpauth://totp/Ada?secret=JBSWY3DPEHPK3PXP");
        });
        let OtpDecision::Skipped { detail } = from_entry(&db.root().entries().next().unwrap())
        else {
            panic!("expected a skip");
        };
        assert_eq!(detail, "TOTP secret is shorter than 128 bits");
        assert!(!detail.contains("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn malformed_otpauth_and_unknown_algorithm_are_skipped_without_secrets() {
        for raw in [
            format!("otpauth://totp/Ada?secret={SECRET}&period=not-a-number"),
            format!("otpauth://totp/Ada?secret={SECRET}&algorithm=MD5"),
            "otpauth://totp/Ada".to_string(),
        ] {
            let db = entry_with(|entry| entry.set_unprotected(fields::OTP, raw));
            let OtpDecision::Skipped { detail } = from_entry(&db.root().entries().next().unwrap())
            else {
                panic!("expected a skip");
            };
            assert!(!detail.is_empty());
            assert!(!detail.contains(SECRET));
        }
    }

    #[test]
    fn malformed_percent_encoding_is_skipped_without_panicking() {
        for suffix in ["%", "%0", "%GG", "%FF", "%€"] {
            let raw = format!("otpauth://totp/Ada?secret={SECRET}{suffix}");
            assert!(parse_otpauth(&raw).is_err());
        }
    }

    #[test]
    fn invalid_algorithm_does_not_echo_the_field_value() {
        let value = uuid::Uuid::new_v4().to_string();
        let error = parse_algorithm(&value).unwrap_err();
        assert!(!error.contains(&value), "algorithm diagnostic leaked input");
        assert!(parse_algorithm("MD5").is_err());
    }

    #[test]
    fn hotp_otpauth_keeps_the_counter() {
        let db = entry_with(|entry| {
            entry.set_unprotected(
                fields::OTP,
                format!("otpauth://hotp/Site:ada?secret={SECRET}&counter=7&digits=6"),
            );
        });
        let OtpDecision::Value(Otp::Hotp(ref hotp)) =
            from_entry(&db.root().entries().next().unwrap())
        else {
            panic!("expected a hotp");
        };
        assert_eq!(hotp.secret, SECRET);
        assert_eq!(hotp.counter, 7);
        assert_eq!(hotp.digits, 6);
    }

    #[test]
    fn hotp_without_counter_is_skipped() {
        let db = entry_with(|entry| {
            entry.set_unprotected(
                fields::OTP,
                format!("otpauth://hotp/Site:ada?secret={SECRET}"),
            );
        });
        let OtpDecision::Skipped { detail } = from_entry(&db.root().entries().next().unwrap())
        else {
            panic!("expected a skip");
        };
        assert_eq!(detail, "otpauth HOTP URL has no counter");
        assert!(!detail.contains(SECRET));
    }

    #[test]
    fn hmac_fields_default_the_counter_to_zero() {
        let db = entry_with(|entry| {
            entry.set_unprotected("HmacOtp-Secret-Base32", SECRET);
            entry.set_unprotected("HmacOtp-Algorithm", "SHA512");
        });
        let OtpDecision::Value(Otp::Hotp(ref hotp)) =
            from_entry(&db.root().entries().next().unwrap())
        else {
            panic!("expected a hotp");
        };
        assert_eq!(hotp.secret, SECRET);
        assert_eq!(hotp.counter, 0);
        assert_eq!(hotp.algorithm, TotpAlgorithm::Sha512);
    }
}
