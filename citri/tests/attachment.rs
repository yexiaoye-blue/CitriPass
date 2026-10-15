use std::fs;

use vault_attachment_store::FileAttachmentStore;
use vault_core::{ItemData, ItemDraft, ATTACHMENT_CHUNK_SIZE};
use vault_storage::VaultSession;
use vault_storage_sqlite::SqliteStore;

#[test]
fn sqlite_and_file_drivers_commit_an_attachment_together() {
    let root = std::env::temp_dir().join(format!("citri-attachment-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let database = root.join("vault.db");
    let password = format!("attachment-host-{}", std::process::id());
    let marker = b"citri-attachment-marker";
    let mut plaintext = vec![0u8; ATTACHMENT_CHUNK_SIZE + marker.len()];
    plaintext[ATTACHMENT_CHUNK_SIZE..].copy_from_slice(marker);

    let (mut session, _) =
        VaultSession::create(SqliteStore::open(&database).unwrap(), &password).unwrap();
    let item = session
        .create_item(ItemDraft::new("Note", ItemData::SecureNote))
        .unwrap();
    let files = FileAttachmentStore::new(root.join("files")).unwrap();
    let reference = session
        .add_attachment(
            &files,
            item.item_id,
            "photo.bin",
            "application/octet-stream",
            &plaintext,
        )
        .unwrap();
    drop(session.into_store());

    let stored = fs::read(&database).unwrap();
    assert!(!stored.windows(marker.len()).any(|window| window == marker));

    let mut session = VaultSession::open(SqliteStore::open(&database).unwrap(), &password).unwrap();
    let read = session
        .read_attachment(&files, item.item_id, reference.attachment_id)
        .unwrap();
    assert_eq!(read, plaintext);
    session
        .delete_attachment(&files, item.item_id, reference.attachment_id)
        .unwrap();
    assert!(session
        .get_item(item.item_id)
        .unwrap()
        .attachments
        .is_empty());
    fs::remove_dir_all(root).unwrap();
}
