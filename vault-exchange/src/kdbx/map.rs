//! Map a decrypted KeePass database onto an [`ImportPlan`](crate::ImportPlan).

use keepass::db::{fields, EntryId, EntryRef, GroupId, GroupRef};
use keepass::Database;
use uuid::Uuid;
use vault_core::{CustomField, ItemData, ItemDraft, Otp};

use crate::import::{ImportPlan, PlannedFolder, PlannedItem, SkipReason, SkippedRecord};

use super::totp::{self, OtpDecision};

const IMPORTED_ENTRY: &str = "Imported entry";
const IMPORTED_FOLDER: &str = "Imported folder";

pub(crate) fn map_database(db: &Database) -> ImportPlan {
    let mut plan = ImportPlan::default();
    // The KeePass root is the database container. Its children become the vault root.
    walk_group(db.root(), None, true, db.meta.recyclebin_uuid, &mut plan);
    plan
}

fn walk_group(
    group: GroupRef<'_>,
    parent_source_id: Option<&str>,
    is_root: bool,
    recycle_bin: Option<Uuid>,
    plan: &mut ImportPlan,
) {
    let group_uuid = group.id().uuid();
    if recycle_bin == Some(group_uuid) {
        skip_recycle(group, plan);
        return;
    }

    let source_id = group_uuid.to_string();
    let folder_key = if is_root {
        None
    } else {
        plan.folders
            .push(map_folder(&group, &source_id, parent_source_id));
        report_group_extras(&group, &source_id, plan);
        Some(source_id)
    };

    let children: Vec<GroupId> = group.group_ids().collect();
    for child_id in children {
        if let Some(child) = group.group(child_id) {
            walk_group(child, folder_key.as_deref(), false, recycle_bin, plan);
        }
    }

    let entries: Vec<EntryId> = group.entry_ids().collect();
    for entry_id in entries {
        if let Some(entry) = group.entry(entry_id) {
            map_entry(entry, folder_key.clone(), plan);
        }
    }
}

fn map_folder(
    group: &GroupRef<'_>,
    source_id: &str,
    parent_source_id: Option<&str>,
) -> PlannedFolder {
    let mut draft = ItemDraft::new(
        group_title(&group.name),
        ItemData::Folder { parent_id: None },
    );
    draft.notes = group.notes.clone().unwrap_or_default();
    draft.tags = clean_tags(&group.tags);
    PlannedFolder {
        source_id: source_id.to_string(),
        parent_source_id: parent_source_id.map(str::to_string),
        draft,
    }
}

fn report_group_extras(group: &GroupRef<'_>, source_id: &str, plan: &mut ImportPlan) {
    let title = group_title(&group.name);
    if group.custom_icon().is_some() {
        plan.skipped
            .push(skip(source_id, &title, SkipReason::CustomIcon, ""));
    }
    report_custom_data(group.custom_data.iter(), source_id, &title, plan);
}

fn skip_recycle(group: GroupRef<'_>, plan: &mut ImportPlan) {
    let source_id = group.id().uuid().to_string();
    let title = group_title(&group.name);
    plan.skipped
        .push(skip(&source_id, &title, SkipReason::RecycleBin, ""));

    let children: Vec<GroupId> = group.group_ids().collect();
    for child_id in children {
        if let Some(child) = group.group(child_id) {
            skip_recycle(child, plan);
        }
    }
    let entries: Vec<EntryId> = group.entry_ids().collect();
    for entry_id in entries {
        if let Some(entry) = group.entry(entry_id) {
            plan.skipped.push(skip(
                &entry.id().uuid().to_string(),
                &entry_title(&entry),
                SkipReason::RecycleBin,
                "",
            ));
        }
    }
}

fn map_entry(entry: EntryRef<'_>, folder_source_id: Option<String>, plan: &mut ImportPlan) {
    let source_id = entry.id().uuid().to_string();
    let title = entry_title(&entry);
    let notes = entry.get(fields::NOTES).unwrap_or("").to_string();
    let username = entry.get_username().unwrap_or("").trim().to_string();
    let password = entry.get_password().unwrap_or("").to_string();
    let urls = entry_urls(&entry);
    let otp = take_otp(&entry, &source_id, &title, plan);
    let mut draft = if login_material(&username, &password, &urls, otp.is_some()) {
        ItemDraft::new(
            title.clone(),
            ItemData::Login {
                username,
                password,
                urls,
                otp,
            },
        )
    } else {
        ItemDraft::new(title.clone(), ItemData::SecureNote)
    };
    draft.notes = notes;
    draft.tags = clean_tags(&entry.tags);
    draft.custom_fields = custom_fields(&entry);

    report_entry_extras(&entry, &source_id, &title, plan);
    plan.items.push(PlannedItem {
        source_id,
        folder_source_id,
        draft,
    });
}

fn login_material(username: &str, password: &str, urls: &[String], has_otp: bool) -> bool {
    has_otp || !username.is_empty() || !password.is_empty() || !urls.is_empty()
}

fn entry_urls(entry: &EntryRef<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    push_url(&mut urls, entry.get_url());
    push_url(&mut urls, entry.override_url.as_deref());
    urls
}

fn push_url(urls: &mut Vec<String>, value: Option<&str>) {
    let Some(url) = value.map(str::trim).filter(|url| !url.is_empty()) else {
        return;
    };
    if urls.iter().any(|existing| existing == url) {
        return;
    }
    urls.push(url.to_string());
}

fn take_otp(
    entry: &EntryRef<'_>,
    source_id: &str,
    title: &str,
    plan: &mut ImportPlan,
) -> Option<Otp> {
    match totp::from_entry(entry) {
        OtpDecision::Absent => None,
        OtpDecision::Value(otp) => Some(otp),
        OtpDecision::Skipped { detail } => {
            plan.skipped
                .push(skip(source_id, title, SkipReason::Otp, &detail));
            None
        }
    }
}

fn report_entry_extras(entry: &EntryRef<'_>, source_id: &str, title: &str, plan: &mut ImportPlan) {
    if let Some(history) = entry.history.as_ref() {
        let count = history.get_entries().len();
        if count > 0 {
            let detail = if count == 1 {
                "1 older version".to_string()
            } else {
                format!("{count} older versions")
            };
            plan.skipped
                .push(skip(source_id, title, SkipReason::History, &detail));
        }
    }
    if has_autotype(entry) {
        plan.skipped
            .push(skip(source_id, title, SkipReason::AutoType, ""));
    }
    if entry.custom_icon().is_some() {
        plan.skipped
            .push(skip(source_id, title, SkipReason::CustomIcon, ""));
    }

    let mut attachment_names: Vec<&str> = entry.attachments_named().map(|(name, _)| name).collect();
    attachment_names.sort_unstable();
    for name in attachment_names {
        plan.skipped
            .push(skip(source_id, title, SkipReason::Attachment, name));
    }
    report_custom_data(entry.custom_data.iter(), source_id, title, plan);
}

fn has_autotype(entry: &EntryRef<'_>) -> bool {
    entry.autotype.as_ref().is_some_and(|auto| {
        auto.enabled
            || auto
                .default_sequence
                .as_ref()
                .is_some_and(|sequence| !sequence.trim().is_empty())
            || !auto.associations.is_empty()
    })
}

fn report_custom_data<'a>(
    values: impl Iterator<Item = (&'a String, &'a keepass::db::CustomDataItem)>,
    source_id: &str,
    title: &str,
    plan: &mut ImportPlan,
) {
    let mut names: Vec<&str> = values
        .filter(|(_, item)| item.value.is_some())
        .map(|(name, _)| name.as_str())
        .collect();
    names.sort_unstable();
    for name in names {
        plan.skipped
            .push(skip(source_id, title, SkipReason::CustomData, name));
    }
}

fn custom_fields(entry: &EntryRef<'_>) -> Vec<CustomField> {
    let mut fields: Vec<CustomField> = entry
        .fields
        .iter()
        .filter(|(name, value)| !is_reserved(name) && !value.as_str().is_empty())
        .map(|(name, value)| CustomField {
            name: name.clone(),
            value: value.as_str().to_string(),
            concealed: value.is_protected(),
        })
        .collect();
    fields.sort_by(|left, right| left.name.cmp(&right.name));
    fields
}

fn is_reserved(name: &str) -> bool {
    matches!(
        name,
        fields::TITLE
            | fields::USERNAME
            | fields::PASSWORD
            | fields::URL
            | fields::NOTES
            | fields::OTP
            | "TOTP Seed"
            | "TOTP Settings"
            | "TimeOtp-Secret-Base32"
            | "TimeOtp-Secret"
            | "TimeOtp-Period"
            | "TimeOtp-Length"
            | "TimeOtp-Digits"
            | "TimeOtp-Algorithm"
            | "HmacOtp-Secret"
            | "HmacOtp-Secret-Base32"
            | "HmacOtp-Secret-Base64"
            | "HmacOtp-Secret-Hex"
            | "HmacOtp-Counter"
            | "HmacOtp-Length"
            | "HmacOtp-Digits"
            | "HmacOtp-Algorithm"
    )
}

fn entry_title(entry: &EntryRef<'_>) -> String {
    let title = entry.get_title().unwrap_or("").trim();
    if !title.is_empty() {
        return title.to_string();
    }
    let username = entry.get_username().unwrap_or("").trim();
    if !username.is_empty() {
        return username.to_string();
    }
    IMPORTED_ENTRY.to_string()
}

fn group_title(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        IMPORTED_FOLDER.to_string()
    } else {
        trimmed.to_string()
    }
}

fn clean_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .map(|tag| tag.trim())
        .filter(|tag| !tag.is_empty())
        .map(str::to_string)
        .collect()
}

fn skip(source_id: &str, title: &str, reason: SkipReason, detail: &str) -> SkippedRecord {
    SkippedRecord {
        source_id: source_id.to_string(),
        title: title.to_string(),
        reason,
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::{fields, AutoType, CustomDataItem, CustomDataValue, Value};
    use keepass::Database;
    use vault_core::{ItemData, Otp, TotpAlgorithm};

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn item<'a>(plan: &'a ImportPlan, title: &str) -> &'a PlannedItem {
        plan.items
            .iter()
            .find(|item| item.draft.title == title)
            .unwrap_or_else(|| panic!("missing item {title}"))
    }

    fn folder<'a>(plan: &'a ImportPlan, title: &str) -> &'a PlannedFolder {
        plan.folders
            .iter()
            .find(|folder| folder.draft.title == title)
            .unwrap_or_else(|| panic!("missing folder {title}"))
    }

    fn skipped<'a>(plan: &'a ImportPlan, title: &str, reason: SkipReason) -> &'a SkippedRecord {
        plan.skipped
            .iter()
            .find(|record| record.title == title && record.reason == reason)
            .unwrap_or_else(|| panic!("missing skip {title} {reason:?}"))
    }

    #[test]
    fn maps_nested_folders_and_login_fields() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut work = root.add_group();
            work.name = " Work ".into();
            work.notes = Some("office".into());
            work.tags.push("team".into());
            {
                let mut nested = work.add_group();
                nested.name = "Nested".into();
                nested.add_entry().set_unprotected(fields::TITLE, "Inner");
            }
            let mut mail = work.add_entry();
            mail.set_unprotected(fields::TITLE, "Mail");
            mail.set_unprotected(fields::USERNAME, " ada ");
            mail.set_protected(fields::PASSWORD, "secret");
            mail.set_unprotected(fields::URL, "https://example.com");
            mail.override_url = Some("https://example.com/login".into());
            mail.set_unprotected(fields::NOTES, "hello");
            mail.tags.push(" inbox ".into());
            mail.set_protected("PIN", "1234");
            mail.set_unprotected("Site", "example");
            root.add_entry().set_unprotected(fields::TITLE, "Loose");
        }

        let plan = map_database(&db);
        let root_id = db.root().id().uuid().to_string();
        assert!(plan
            .folders
            .iter()
            .all(|folder| folder.source_id != root_id));

        let work = folder(&plan, "Work");
        assert_eq!(work.parent_source_id, None);
        assert_eq!(work.draft.notes, "office");
        assert_eq!(work.draft.tags, vec!["team".to_string()]);
        assert!(work.draft.folder_id.is_none());

        let nested = folder(&plan, "Nested");
        assert_eq!(
            nested.parent_source_id.as_deref(),
            Some(work.source_id.as_str())
        );

        let mail = item(&plan, "Mail");
        assert_eq!(
            mail.folder_source_id.as_deref(),
            Some(work.source_id.as_str())
        );
        assert!(mail.draft.folder_id.is_none());
        assert_eq!(mail.draft.notes, "hello");
        assert_eq!(mail.draft.tags, vec!["inbox".to_string()]);
        assert_eq!(mail.draft.custom_fields.len(), 2);
        assert_eq!(mail.draft.custom_fields[0].name, "PIN");
        assert!(mail.draft.custom_fields[0].concealed);
        assert_eq!(mail.draft.custom_fields[1].name, "Site");
        assert!(!mail.draft.custom_fields[1].concealed);
        match &mail.draft.data {
            ItemData::Login {
                username,
                password,
                urls,
                otp,
            } => {
                assert_eq!(username, "ada");
                assert_eq!(password, "secret");
                assert_eq!(
                    urls,
                    &[
                        "https://example.com".to_string(),
                        "https://example.com/login".to_string()
                    ]
                );
                assert!(otp.is_none());
            }
            _ => panic!("login"),
        }
        assert_eq!(
            item(&plan, "Inner").folder_source_id.as_deref(),
            Some(nested.source_id.as_str())
        );
        assert_eq!(item(&plan, "Loose").folder_source_id, None);
        assert!(matches!(
            item(&plan, "Loose").draft.data,
            ItemData::SecureNote
        ));
    }

    #[test]
    fn empty_titles_fall_back_to_username_then_placeholder() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.add_entry().set_unprotected(fields::USERNAME, "ada");
            root.add_entry()
                .set_unprotected(fields::NOTES, "only a note");
            let mut blank = root.add_group();
            blank.name = "   ".into();
        }
        let plan = map_database(&db);
        assert!(plan.items.iter().any(|item| item.draft.title == "ada"));
        assert!(plan
            .items
            .iter()
            .any(|item| item.draft.title == IMPORTED_ENTRY));
        assert!(plan
            .folders
            .iter()
            .any(|folder| folder.draft.title == IMPORTED_FOLDER));
    }

    #[test]
    fn reports_parts_that_are_not_copied() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, "Old");
            entry.set_unprotected(fields::USERNAME, "ada");
            {
                let mut tracked = entry.track_changes();
                tracked.set_unprotected(fields::PASSWORD, "next");
            }
            entry.autotype = Some(AutoType {
                enabled: true,
                default_sequence: Some("{PASSWORD}".into()),
                ..AutoType::default()
            });
            entry.set_icon_custom_new(vec![1, 2, 3, 4]);
            entry.add_attachment("token.txt", Value::unprotected(b"abc".to_vec()));
            entry.custom_data.insert(
                "windows-account".into(),
                CustomDataItem {
                    value: Some(CustomDataValue::Binary(vec![9, 9, 9])),
                    last_modification_time: None,
                },
            );
        }
        let plan = map_database(&db);
        assert!(matches!(
            item(&plan, "Old").draft.data,
            ItemData::Login { .. }
        ));
        assert_eq!(
            skipped(&plan, "Old", SkipReason::History).detail,
            "1 older version"
        );
        assert_eq!(skipped(&plan, "Old", SkipReason::AutoType).detail, "");
        assert_eq!(skipped(&plan, "Old", SkipReason::CustomIcon).detail, "");
        assert_eq!(
            skipped(&plan, "Old", SkipReason::Attachment).detail,
            "token.txt"
        );
        assert_eq!(
            skipped(&plan, "Old", SkipReason::CustomData).detail,
            "windows-account"
        );
        assert!(!skipped(&plan, "Old", SkipReason::CustomData)
            .detail
            .contains("9"));
    }

    #[test]
    fn recycle_bin_is_matched_by_id() {
        let mut db = Database::new();
        let bin_id = {
            let mut root = db.root_mut();
            let mut named = root.add_group();
            named.name = "Recycle Bin".into();
            named.add_entry().set_unprotected(fields::TITLE, "Kept");
            let mut bin = root.add_group();
            bin.name = "Trash".into();
            bin.add_entry().set_unprotected(fields::TITLE, "Gone");
            bin.id().uuid()
        };
        db.meta.recyclebin_uuid = Some(bin_id);
        let plan = map_database(&db);
        assert!(plan
            .folders
            .iter()
            .any(|folder| folder.draft.title == "Recycle Bin"));
        assert!(plan.items.iter().any(|item| item.draft.title == "Kept"));
        assert!(plan.items.iter().all(|item| item.draft.title != "Gone"));
        assert!(plan
            .folders
            .iter()
            .all(|folder| folder.draft.title != "Trash"));
        assert_eq!(
            skipped(&plan, "Trash", SkipReason::RecycleBin).source_id,
            bin_id.to_string()
        );
        assert_eq!(
            skipped(&plan, "Gone", SkipReason::RecycleBin).reason,
            SkipReason::RecycleBin
        );
    }

    #[test]
    fn maps_supported_totp_and_skips_a_short_secret() {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut otp = root.add_entry();
            otp.set_unprotected(fields::TITLE, "Otp");
            otp.set_unprotected(
                fields::OTP,
                format!("otpauth://totp/Example:ada?secret={SECRET}&period=30&digits=6"),
            );
            let mut seed = root.add_entry();
            seed.set_unprotected(fields::TITLE, "Seed");
            seed.set_unprotected("TOTP Seed", SECRET);
            seed.set_unprotected("TOTP Settings", "30;6;SHA512");
            let mut timeotp = root.add_entry();
            timeotp.set_unprotected(fields::TITLE, "Time");
            timeotp.set_unprotected("TimeOtp-Secret-Base32", SECRET);
            timeotp.set_unprotected("TimeOtp-Period", "15");
            timeotp.set_unprotected("TimeOtp-Length", "7");
            timeotp.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA256");
            let mut short = root.add_entry();
            short.set_unprotected(fields::TITLE, "Short");
            short.set_unprotected(fields::USERNAME, "ada");
            short.set_unprotected(fields::OTP, "otpauth://totp/Ada?secret=JBSWY3DPEHPK3PXP");
        }
        let plan = map_database(&db);
        match &item(&plan, "Otp").draft.data {
            ItemData::Login { username, otp, .. } => {
                assert_eq!(username, "");
                let Otp::Totp(totp) = otp.as_ref().unwrap() else {
                    panic!("totp");
                };
                assert_eq!(totp.secret, SECRET);
                assert_eq!(totp.digits, 6);
                assert_eq!(totp.algorithm, TotpAlgorithm::Sha1);
            }
            _ => panic!("otp login"),
        }
        match &item(&plan, "Seed").draft.data {
            ItemData::Login {
                otp: Some(Otp::Totp(totp)),
                ..
            } => assert_eq!(totp.algorithm, TotpAlgorithm::Sha512),
            _ => panic!("seed"),
        }
        match &item(&plan, "Time").draft.data {
            ItemData::Login {
                otp: Some(Otp::Totp(totp)),
                ..
            } => {
                assert_eq!(totp.period, 15);
                assert_eq!(totp.digits, 7);
                assert_eq!(totp.algorithm, TotpAlgorithm::Sha256);
            }
            _ => panic!("time"),
        }
        assert!(item(&plan, "Time").draft.custom_fields.is_empty());
        match &item(&plan, "Short").draft.data {
            ItemData::Login {
                otp: None,
                username,
                ..
            } => assert_eq!(username, "ada"),
            _ => panic!("short secret still imports the login"),
        }
        assert_eq!(
            skipped(&plan, "Short", SkipReason::Otp).detail,
            "TOTP secret is shorter than 128 bits"
        );
    }
}
