//! Write an [`ImportPlan`](crate::ImportPlan) into a vault.

use std::collections::HashMap;

use uuid::Uuid;
use vault_core::{ItemData, ItemDraft, UnlockedVault};

use crate::import::{ImportPlan, PlannedFolder, PlannedItem};

/// Accepts item drafts and returns the id it stored.
///
/// [`UnlockedVault`](vault_core::UnlockedVault) implements this with `create_item`.
/// Tests and other hosts can implement it without opening a vault.
pub trait ItemWriter {
    /// Failure from the destination. It is returned as [`ApplyError::Write`].
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store one new item.
    ///
    /// # Errors
    ///
    /// Returns the destination error unchanged in meaning. The adapter wraps it.
    fn write_item(&mut self, draft: ItemDraft) -> Result<Uuid, Self::Error>;
}

impl ItemWriter for UnlockedVault {
    type Error = vault_core::Error;

    fn write_item(&mut self, draft: ItemDraft) -> Result<Uuid, Self::Error> {
        self.create_item(draft).map(|item| item.item_id)
    }
}

/// Ids assigned while applying a plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApplyReport {
    /// Folders in the order they were written.
    pub folders: Vec<WrittenRecord>,
    /// Other items in the order they were written.
    pub items: Vec<WrittenRecord>,
}

/// One source record and the vault id created for it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct WrittenRecord {
    /// Format-specific id from the plan.
    pub source_id: String,
    /// Id returned by the [`ItemWriter`].
    pub item_id: Uuid,
}

/// Apply stopped. Records written before this error stay in the destination.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApplyError<E: std::error::Error + 'static> {
    /// A child named a parent that was not written earlier in the plan.
    #[error("imported record `{source_id}` is missing parent `{parent_source_id}`")]
    MissingParent {
        /// Record that could not be placed.
        source_id: String,
        /// Parent id that was not in the plan before this record.
        parent_source_id: String,
    },

    /// Two planned records used the same source id.
    #[error("imported record `{source_id}` was already written")]
    DuplicateSource {
        /// Repeated source id.
        source_id: String,
    },

    /// A folder entry was not a folder draft.
    #[error("imported record `{source_id}` is not a folder")]
    NotAFolder {
        /// Source id from the folder list.
        source_id: String,
    },

    /// The destination rejected a draft.
    #[error("writing imported record `{source_id}` failed")]
    Write {
        /// Source id that was not stored.
        source_id: String,
        /// Destination failure.
        #[source]
        source: E,
    },
}

/// Create every folder, then every other item.
///
/// Parent folders are written before their children. A failure leaves the
/// earlier records in the destination; the rest of the plan is dropped.
///
/// # Errors
///
/// See [`ApplyError`]. The plan is consumed either way.
pub fn apply_plan<W: ItemWriter>(
    writer: &mut W,
    plan: ImportPlan,
) -> Result<ApplyReport, ApplyError<W::Error>> {
    let mut written = HashMap::with_capacity(plan.folders.len() + plan.items.len());
    let mut report = ApplyReport {
        folders: Vec::with_capacity(plan.folders.len()),
        items: Vec::with_capacity(plan.items.len()),
    };

    for folder in plan.folders {
        let record = write_folder(writer, &mut written, folder)?;
        report.folders.push(record);
    }
    for item in plan.items {
        let record = write_item(writer, &mut written, item)?;
        report.items.push(record);
    }
    Ok(report)
}

fn write_folder<W: ItemWriter>(
    writer: &mut W,
    written: &mut HashMap<String, Uuid>,
    folder: PlannedFolder,
) -> Result<WrittenRecord, ApplyError<W::Error>> {
    let source_id = folder.source_id;
    ensure_new(&source_id, written)?;
    let parent = match folder.parent_source_id {
        Some(parent_source_id) => Some(require_parent(written, &source_id, &parent_source_id)?),
        None => None,
    };
    let mut draft = folder.draft;
    draft.folder_id = parent;
    match &mut draft.data {
        ItemData::Folder { parent_id } => *parent_id = parent,
        _ => return Err(ApplyError::NotAFolder { source_id }),
    }
    let item_id = write_draft(writer, &source_id, draft)?;
    written.insert(source_id.clone(), item_id);
    Ok(WrittenRecord { source_id, item_id })
}

fn write_item<W: ItemWriter>(
    writer: &mut W,
    written: &mut HashMap<String, Uuid>,
    item: PlannedItem,
) -> Result<WrittenRecord, ApplyError<W::Error>> {
    let source_id = item.source_id;
    ensure_new(&source_id, written)?;
    let folder_id = match item.folder_source_id {
        Some(parent_source_id) => Some(require_parent(written, &source_id, &parent_source_id)?),
        None => None,
    };
    let mut draft = item.draft;
    draft.folder_id = folder_id;
    let item_id = write_draft(writer, &source_id, draft)?;
    written.insert(source_id.clone(), item_id);
    Ok(WrittenRecord { source_id, item_id })
}

fn ensure_new<E: std::error::Error + 'static>(
    source_id: &str,
    written: &HashMap<String, Uuid>,
) -> Result<(), ApplyError<E>> {
    if written.contains_key(source_id) {
        return Err(ApplyError::DuplicateSource {
            source_id: source_id.to_string(),
        });
    }
    Ok(())
}

fn require_parent<E: std::error::Error + 'static>(
    written: &HashMap<String, Uuid>,
    source_id: &str,
    parent_source_id: &str,
) -> Result<Uuid, ApplyError<E>> {
    written
        .get(parent_source_id)
        .copied()
        .ok_or_else(|| ApplyError::MissingParent {
            source_id: source_id.to_string(),
            parent_source_id: parent_source_id.to_string(),
        })
}

fn write_draft<W: ItemWriter>(
    writer: &mut W,
    source_id: &str,
    draft: ItemDraft,
) -> Result<Uuid, ApplyError<W::Error>> {
    writer
        .write_item(draft)
        .map_err(|source| ApplyError::Write {
            source_id: source_id.to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::PlannedFolder;
    use vault_core::{ItemData, ItemDraft};

    #[derive(Debug)]
    struct WriteFail;

    impl std::fmt::Display for WriteFail {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("destination rejected the item")
        }
    }

    impl std::error::Error for WriteFail {}

    struct MemoryWriter {
        next: u128,
        fail_on: Option<u128>,
        items: Vec<(Uuid, ItemDraft)>,
    }

    impl MemoryWriter {
        fn new() -> Self {
            Self {
                next: 0,
                fail_on: None,
                items: Vec::new(),
            }
        }
    }

    impl ItemWriter for MemoryWriter {
        type Error = WriteFail;

        fn write_item(&mut self, draft: ItemDraft) -> Result<Uuid, Self::Error> {
            self.next += 1;
            if self.fail_on == Some(self.next) {
                return Err(WriteFail);
            }
            let item_id = Uuid::from_u128(self.next);
            self.items.push((item_id, draft));
            Ok(item_id)
        }
    }

    fn folder(source_id: &str, parent: Option<&str>, title: &str) -> PlannedFolder {
        PlannedFolder {
            source_id: source_id.to_string(),
            parent_source_id: parent.map(str::to_string),
            draft: ItemDraft::new(title, ItemData::Folder { parent_id: None }),
        }
    }

    fn login(source_id: &str, folder: Option<&str>, title: &str) -> PlannedItem {
        PlannedItem {
            source_id: source_id.to_string(),
            folder_source_id: folder.map(str::to_string),
            draft: ItemDraft::new(
                title,
                ItemData::Login {
                    username: "ada".to_string(),
                    password: "secret".to_string(),
                    urls: Vec::new(),
                    otp: None,
                },
            ),
        }
    }

    #[test]
    fn writes_parent_folders_before_children() {
        let plan = ImportPlan {
            folders: vec![
                folder("work", None, "Work"),
                folder("nested", Some("work"), "Nested"),
            ],
            items: vec![
                login("inner", Some("nested"), "Inner"),
                login("mail", Some("work"), "Mail"),
                login("loose", None, "Loose"),
            ],
            skipped: Vec::new(),
        };
        let mut writer = MemoryWriter::new();
        let report = apply_plan(&mut writer, plan).unwrap();

        let titles: Vec<&str> = writer
            .items
            .iter()
            .map(|(_, draft)| draft.title.as_str())
            .collect();
        assert_eq!(titles, vec!["Work", "Nested", "Inner", "Mail", "Loose"]);

        let work = report.folders[0].item_id;
        let nested = report.folders[1].item_id;
        assert_eq!(writer.items[0].1.data, ItemData::Folder { parent_id: None });
        assert_eq!(writer.items[1].1.folder_id, Some(work));
        assert_eq!(
            writer.items[1].1.data,
            ItemData::Folder {
                parent_id: Some(work)
            }
        );
        assert_eq!(writer.items[2].1.folder_id, Some(nested));
        assert_eq!(writer.items[3].1.folder_id, Some(work));
        assert_eq!(writer.items[4].1.folder_id, None);
    }

    #[test]
    fn missing_parent_stops_before_that_record() {
        let plan = ImportPlan {
            folders: vec![folder("child", Some("missing"), "Child")],
            items: Vec::new(),
            skipped: Vec::new(),
        };
        let mut writer = MemoryWriter::new();
        let error = apply_plan(&mut writer, plan).unwrap_err();
        assert!(matches!(
            error,
            ApplyError::MissingParent { ref source_id, ref parent_source_id }
                if source_id == "child" && parent_source_id == "missing"
        ));
        assert!(writer.items.is_empty());
    }

    #[test]
    fn duplicate_source_id_is_rejected() {
        let plan = ImportPlan {
            folders: vec![folder("work", None, "Work"), folder("work", None, "Again")],
            items: Vec::new(),
            skipped: Vec::new(),
        };
        let error = apply_plan(&mut MemoryWriter::new(), plan).unwrap_err();
        assert!(
            matches!(error, ApplyError::DuplicateSource { ref source_id } if source_id == "work")
        );
    }

    #[test]
    fn non_folder_in_the_folder_list_is_rejected() {
        let plan = ImportPlan {
            folders: vec![PlannedFolder {
                source_id: "bad".to_string(),
                parent_source_id: None,
                draft: ItemDraft::new("Nope", ItemData::SecureNote),
            }],
            items: Vec::new(),
            skipped: Vec::new(),
        };
        let error = apply_plan(&mut MemoryWriter::new(), plan).unwrap_err();
        assert!(matches!(error, ApplyError::NotAFolder { ref source_id } if source_id == "bad"));
    }

    #[test]
    fn destination_error_keeps_earlier_records() {
        let plan = ImportPlan {
            folders: vec![folder("work", None, "Work")],
            items: vec![login("mail", Some("work"), "Mail")],
            skipped: Vec::new(),
        };
        let mut writer = MemoryWriter::new();
        writer.fail_on = Some(2);
        let error = apply_plan(&mut writer, plan).unwrap_err();
        assert!(matches!(error, ApplyError::Write { ref source_id, .. } if source_id == "mail"));
        assert_eq!(writer.items.len(), 1);
    }

    #[test]
    fn unlocked_vault_implements_item_writer() {
        fn assert_writer<W: ItemWriter>() {}
        assert_writer::<UnlockedVault>();
    }
}
