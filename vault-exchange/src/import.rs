//! A preview of records that can be written into an open vault.

use vault_core::ItemDraft;

/// Bytes and credentials for one source database.
///
/// Extra credential kinds can be added without changing [`crate::Importer`].
/// Adapters that do not understand a credential return [`crate::Error`].
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ImportSource<'a> {
    /// Complete source file.
    pub bytes: &'a [u8],
    /// Database password. An empty password is passed through to the format.
    pub password: &'a str,
    /// Optional key file. The bytes are the file contents, not a path.
    pub key_file: Option<&'a [u8]>,
}

impl<'a> ImportSource<'a> {
    /// Password-only source.
    pub fn new(bytes: &'a [u8], password: &'a str) -> Self {
        Self {
            bytes,
            password,
            key_file: None,
        }
    }

    /// Add a key file.
    pub fn with_key_file(mut self, key_file: &'a [u8]) -> Self {
        self.key_file = Some(key_file);
        self
    }
}

/// Reads one format into an [`ImportPlan`].
///
/// The importer does not open a CitriPass vault. Callers preview the plan and
/// then pass it to [`crate::apply_plan`].
pub trait Importer: Send + Sync {
    /// Format this importer reads.
    fn format_id(&self) -> crate::FormatId;

    /// Decrypt and map `source`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidSource`] when the bytes or credentials are rejected.
    fn import(&self, source: &ImportSource<'_>) -> crate::Result<ImportPlan>;
}

/// Records ready to write, plus records the adapter refused.
///
/// Folders are listed parent before child. Item drafts leave `folder_id` empty;
/// [`crate::apply_plan`] fills the vault ids after the folders exist.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImportPlan {
    /// Folders, parent before child.
    pub folders: Vec<PlannedFolder>,
    /// Logins, notes, and other non-folder items.
    pub items: Vec<PlannedItem>,
    /// Records or fields that were not imported.
    pub skipped: Vec<SkippedRecord>,
}

/// One folder whose vault id does not exist yet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedFolder {
    /// Format-specific id. Children refer to this value, not a vault id.
    pub source_id: String,
    /// `source_id` of the parent folder. `None` is the vault root.
    pub parent_source_id: Option<String>,
    /// Folder content. Parent links inside the draft are filled during apply.
    pub draft: ItemDraft,
}

/// One non-folder item whose containing folder may not exist yet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlannedItem {
    /// Format-specific id.
    pub source_id: String,
    /// `source_id` of the containing folder. `None` is the vault root.
    pub folder_source_id: Option<String>,
    /// Item content. `folder_id` is filled during apply.
    pub draft: ItemDraft,
}

/// Something the adapter saw and deliberately did not copy.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedRecord {
    /// Format-specific id of the record that owned the skipped data.
    pub source_id: String,
    /// Best available title. This is not a secret.
    pub title: String,
    /// Why the data was left out.
    pub reason: SkipReason,
    /// Extra public context, such as a file name or a TOTP rule.
    ///
    /// This must not contain a password, key, or TOTP secret.
    pub detail: String,
}

/// Why part of a source database was not copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// Older versions of an entry.
    History,
    /// Auto-Type sequences.
    AutoType,
    /// A custom icon.
    CustomIcon,
    /// An attachment. Its bytes are not copied.
    Attachment,
    /// A record in the source recycle bin.
    RecycleBin,
    /// One-time password parameters that this vault cannot store.
    Otp,
    /// Plugin or custom data that has no item field.
    CustomData,
}
