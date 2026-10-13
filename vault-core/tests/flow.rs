use vault_core::*;

fn sample() -> (UnlockedVault, RecoveryKey) {
    UnlockedVault::create("correct horse battery").unwrap()
}

#[test]
fn header_omits_items_and_roundtrips() {
    let (mut vault, _recovery) = sample();
    let before = vault.header().to_bytes().unwrap();
    let item = vault
        .create_item(ItemDraft::new("Note", ItemData::SecureNote))
        .unwrap();
    assert_eq!(vault.header().to_bytes().unwrap(), before);
    let record = vault.export_item(item.item_id).unwrap().to_bytes().unwrap();
    assert!(!record
        .windows(b"Note".len())
        .any(|window| window == b"Note"));
    let sealed = SealedVault::from_bytes(&before).unwrap();
    let mut opened = UnlockedVault::unlock(&sealed, "correct horse battery").unwrap();
    opened
        .import_item(&SealedItem::from_bytes(&record).unwrap(), None)
        .unwrap();
    assert_eq!(opened.list_items().unwrap()[0].title, "Note");
}

#[test]
fn wrong_password_is_unlock_failed() {
    let (vault, _) = sample();
    let header = vault.header();
    assert_eq!(
        UnlockedVault::unlock(&header, "nope").unwrap_err(),
        Error::UnlockFailed
    );
}

#[test]
fn changed_tombstone_does_not_decrypt() {
    let (mut vault, _) = sample();
    let item = vault
        .create_item(ItemDraft::new("Note", ItemData::SecureNote))
        .unwrap();
    let mut bytes = vault.export_item(item.item_id).unwrap().to_bytes().unwrap();
    // magic 4, version 2, vault 16, item 16, revision 8, then the deleted flag.
    bytes[4 + 2 + 16 + 16 + 8] ^= 1;
    let forged = SealedItem::from_bytes(&bytes).unwrap();
    assert_eq!(
        vault.import_item(&forged, Some(1)).unwrap_err(),
        Error::Integrity
    );
}

#[test]
fn recovery_resets_the_master_password_without_rewrapping_items() {
    let (mut vault, recovery) = sample();
    let item = vault
        .create_item(ItemDraft::new("Note", ItemData::SecureNote))
        .unwrap();
    let before = vault.export_item(item.item_id).unwrap().to_bytes().unwrap();
    vault
        .reset_master_password(&recovery, "a different password")
        .unwrap();
    assert_eq!(
        vault.export_item(item.item_id).unwrap().to_bytes().unwrap(),
        before
    );
    let header = vault.header();
    assert!(UnlockedVault::unlock(&header, "correct horse battery").is_err());
    UnlockedVault::unlock(&header, "a different password").unwrap();
    UnlockedVault::unlock_with_recovery_key(&header, &recovery).unwrap();
}

#[test]
fn search_skips_the_password() {
    let (mut vault, _) = sample();
    vault
        .create_login(LoginDraft {
            title: "Mail".into(),
            username: "ada".into(),
            password: "super-secret-value".into(),
            notes: String::new(),
        })
        .unwrap();
    assert!(vault.search("ada").unwrap().len() == 1);
    assert!(vault.search("super-secret-value").unwrap().is_empty());
}

#[test]
fn backup_tag_rejects_tampering() {
    let (mut vault, _) = sample();
    vault
        .create_item(ItemDraft::new("One", ItemData::SecureNote))
        .unwrap();
    vault
        .create_item(ItemDraft::new("Two", ItemData::SecureNote))
        .unwrap();
    let backup = SealedBackup::from_bytes(&vault.backup().unwrap().to_bytes().unwrap()).unwrap();
    let opened = backup.unlock("correct horse battery").unwrap();
    assert_eq!(opened.list_items().unwrap().len(), 2);
    let mut tampered = vault.backup().unwrap().to_bytes().unwrap();
    let tag = tampered.len() - 1;
    tampered[tag] ^= 1;
    assert_eq!(
        SealedBackup::from_bytes(&tampered)
            .unwrap()
            .unlock("correct horse battery")
            .unwrap_err(),
        Error::Integrity
    );
}

#[test]
fn attachment_roundtrip() {
    let (mut vault, _) = sample();
    let item = vault
        .create_item(ItemDraft::new("Note", ItemData::SecureNote))
        .unwrap();
    let mut writer = vault.begin_attachment(item.item_id, 1, 3).unwrap();
    let chunk = writer.encrypt_chunk(b"abc").unwrap();
    let header = writer.finish().unwrap();
    let header = SealedAttachment::from_bytes(&header.to_bytes().unwrap()).unwrap();
    let mut reader = vault.open_attachment(&header).unwrap();
    assert_eq!(reader.decrypt_chunk(&chunk).unwrap().as_slice(), b"abc");
    reader.finish().unwrap();
}

#[test]
fn device_wrap_is_bound_to_the_device() {
    let (vault, _) = sample();
    let key = DeviceKey::generate().unwrap();
    let record = vault
        .wrap_for_device(&key, uuid::Uuid::from_u128(7))
        .unwrap();
    let header = vault.header();
    UnlockedVault::unlock_with_device(&header, &record, &key).unwrap();
    let mut bytes = record.to_bytes().unwrap();
    bytes[4 + 2 + 16] ^= 1;
    let forged = DeviceUnlock::from_bytes(&bytes).unwrap();
    assert_eq!(
        UnlockedVault::unlock_with_device(&header, &forged, &key).unwrap_err(),
        Error::UnlockFailed
    );
}
