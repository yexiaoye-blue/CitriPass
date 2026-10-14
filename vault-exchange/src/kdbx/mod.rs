//! KeePass `.kdbx` import.

mod map;
mod totp;

use std::io::Cursor;

use keepass::{Database, DatabaseKey};

use crate::format::FormatId;
use crate::import::{ImportPlan, ImportSource, Importer};
use crate::{Error, Result};

/// Reads a KeePass 2 database into an [`ImportPlan`](crate::ImportPlan).
///
/// The database password is required by KeePass even when it is empty. A key file
/// is optional. Challenge-response keys, such as a YubiKey, are not read.
///
/// Groups become folders. The KeePass root group itself does not, because it is
/// the database container; its children are placed at the vault root. Entries
/// become logins when they have a username, password, URL, or one-time password, and notes
/// otherwise. An empty title uses the username, then `Imported entry`, so one
/// blank title does not reject the file.
///
/// KeePass may repeat `<String>` and place `Times`, `IconID`, or `History` between
/// those fields. Those entries are still read.
///
/// History, Auto-Type, custom icons, attachments, recycle-bin records, plugin
/// custom data, and one-time passwords this vault cannot store are reported in
/// [`ImportPlan::skipped`](crate::ImportPlan::skipped). The rest of the entry is
/// still imported.
#[derive(Debug, Default, Clone, Copy)]
pub struct KdbxImporter;

impl Importer for KdbxImporter {
    fn format_id(&self) -> FormatId {
        FormatId::KDBX
    }

    fn import(&self, source: &ImportSource<'_>) -> Result<ImportPlan> {
        let mut key = DatabaseKey::new().with_password(source.password);
        if let Some(key_file) = source.key_file {
            let mut cursor = Cursor::new(key_file);
            key = key
                .with_keyfile(&mut cursor)
                .map_err(|err| Error::InvalidSource(err.to_string()))?;
        }
        let database = Database::open(&mut &source.bytes[..], key)
            .map_err(|err| Error::InvalidSource(err.to_string()))?;
        Ok(map::map_database(&database))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::config::KdfConfig;
    use keepass::db::fields;
    use keepass::Database;

    fn cheap_database() -> Database {
        let mut database = Database::new();
        // One AES round keeps the fixture fast. This is not a vault setting.
        database.config.kdf_config = KdfConfig::Aes { rounds: 1 };
        database
    }

    fn save(database: &Database, password: &str, key_file: Option<&[u8]>) -> Vec<u8> {
        let mut key = DatabaseKey::new().with_password(password);
        if let Some(bytes) = key_file {
            key = key.with_keyfile(&mut Cursor::new(bytes)).unwrap();
        }
        let mut output = Vec::new();
        database.save(&mut output, key).unwrap();
        output
    }

    #[test]
    fn round_trip_reads_the_entry_title() {
        let mut database = cheap_database();
        database
            .root_mut()
            .add_entry()
            .set_unprotected(fields::TITLE, "Mail");
        let bytes = save(&database, "secret", None);
        let plan = KdbxImporter
            .import(&ImportSource::new(&bytes, "secret"))
            .unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].draft.title, "Mail");
    }

    #[test]
    fn wrong_password_fails_without_echoing_it() {
        let bytes = save(&cheap_database(), "secret-password", None);
        let error = KdbxImporter
            .import(&ImportSource::new(&bytes, "secret-password-nope"))
            .unwrap_err();
        let text = error.to_string();
        assert!(!text.contains("secret-password"));
        assert!(matches!(error, Error::InvalidSource(_)));
    }

    #[test]
    fn key_file_is_part_of_the_credentials() {
        let mut database = cheap_database();
        database
            .root_mut()
            .add_entry()
            .set_unprotected(fields::TITLE, "Keyed");
        let key_file = b"raw key material";
        let bytes = save(&database, "secret", Some(key_file));
        let missing = KdbxImporter.import(&ImportSource::new(&bytes, "secret"));
        assert!(missing.is_err());
        let plan = KdbxImporter
            .import(&ImportSource::new(&bytes, "secret").with_key_file(key_file))
            .unwrap();
        assert_eq!(plan.items[0].draft.title, "Keyed");
    }

    #[test]
    fn string_fields_split_by_other_elements_are_imported() {
        // Synthetic KDBX 3, password "secret", one entry. Its first <String> sits
        // before <Times>, matching KeePass files whose string fields are not consecutive.
        let bytes = include_bytes!("../../tests/fixtures/interleaved-strings.kdbx");
        let plan = KdbxImporter
            .import(&ImportSource::new(bytes, "secret"))
            .unwrap();
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].draft.title, "Mail");
        assert_eq!(plan.items[0].draft.login_username(), Some("ada"));
    }

    #[test]
    fn saved_kdbx_keeps_protected_totp_after_interleaved_history_and_keyfile() {
        let password = format!("kdbx-{}", uuid::Uuid::new_v4());
        let key_file = uuid::Uuid::new_v4().as_bytes().to_vec();
        let current_password = uuid::Uuid::new_v4().to_string();
        let historical_password = uuid::Uuid::new_v4().to_string();
        let mut database = cheap_database();
        {
            let mut root = database.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Protected OTP");
            entry.set_unprotected(fields::USERNAME, "ada");
            entry.set_protected(fields::PASSWORD, &current_password);
            {
                let mut historical = entry.track_changes();
                historical.set_protected(fields::PASSWORD, &historical_password);
            }
            entry.set_protected(fields::PASSWORD, &current_password);
            entry.set_protected(
                fields::OTP,
                "otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8",
            );
        }

        let bytes = save(&database, &password, Some(&key_file));
        let plan = KdbxImporter
            .import(&ImportSource::new(&bytes, &password).with_key_file(&key_file))
            .unwrap();
        let item = &plan.items[0];
        match &item.draft.data {
            vault_core::ItemData::Login {
                username,
                password,
                otp: Some(vault_core::Otp::Totp(totp)),
                ..
            } => {
                assert_eq!(username, "ada");
                assert_eq!(password, &current_password);
                assert_eq!(totp.digits, 8);
            }
            _ => panic!("expected a login with TOTP"),
        }
        assert!(plan
            .skipped
            .iter()
            .any(|record| record.reason == crate::SkipReason::History));
    }

    #[test]
    fn truncated_bytes_are_rejected() {
        let error = KdbxImporter
            .import(&ImportSource::new(b"not a database", "secret"))
            .unwrap_err();
        assert!(matches!(error, Error::InvalidSource(_)));
    }
}
