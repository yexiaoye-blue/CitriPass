//! Composition root for the formal desktop vault.
//!
//! One SQLite file and one attachment directory are opened here. Commands talk
//! only to VaultSession. Auto-lock lives in this host: after the idle limit it
//! drops the unlocked session, and the vault key with it. The storage driver
//! does not know about idle time.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use vault_attachment_store::FileAttachmentStore;
use vault_core::{
    generate_passphrase, generate_password, password_strength, CustomField, Item, ItemData,
    ItemDraft, LoginPassword, PassphraseOptions, PasswordOptions, Totp,
};
use vault_storage::{SessionError, VaultSession, VaultStore, VaultStoreTransaction};
use vault_storage_sqlite::{SqliteStore, SqliteStoreError};
use vault_sync::{sync_items, HttpSyncError, HttpSyncTransport, SyncReport};
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_IDLE_MINUTES: u32 = 5;
const MIN_IDLE_MINUTES: u32 = 1;
const MAX_IDLE_MINUTES: u32 = 240;

pub(crate) struct HostInner {
    root: PathBuf,
    database: PathBuf,
    attachment_dir: PathBuf,
    attachments: FileAttachmentStore,
    phase: Phase,
    last_sync: Option<SyncView>,
    idle_limit: Duration,
    last_activity: Instant,
    idle_locked: bool,
}

enum Phase {
    Closed,
    Holding(SqliteStore),
    Unlocked(Box<VaultSession<SqliteStore>>),
}

#[derive(Debug, Error)]
pub(crate) enum HostError {
    #[error("这台电脑已经有保险库")]
    AlreadyCreated,
    #[error("还没有保险库")]
    MissingVault,
    #[error("保险库已锁定，请重新输入主密码")]
    Locked,
    #[error("保险库没有处于解锁状态")]
    NotUnlocked,
    #[error("标题不能是空白")]
    EmptyTitle,
    #[error("密码名称不能是空白")]
    EmptyPasswordName,
    #[error("自定义字段的名称不能是空白")]
    EmptyFieldName,
    #[error("生成方式无法识别")]
    UnknownGenerator,
    #[error("条目编号无法识别")]
    BadId,
    #[error("这条条目类型不对")]
    WrongKind,
    #[error("空闲时间要在 1 到 240 分钟之间")]
    IdleRange,
    #[error("同步地址只能是不带账号的 http 或 https")]
    BadUrl,
    #[error("本地应该只有一本保险库")]
    VaultCount,
    #[error("宿主状态不可用")]
    Closed,
    #[error("本地保险库打不开：{0}")]
    Store(String),
    #[error("保险库拒绝了这次操作：{0}")]
    Protocol(String),
    #[error("同步没有完成：{0}")]
    Sync(String),
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HostStatus {
    pub(crate) root: String,
    pub(crate) database_path: String,
    pub(crate) attachment_dir: String,
    pub(crate) phase: String,
    pub(crate) vault_id: Option<String>,
    pub(crate) device_id: Option<String>,
    pub(crate) idle_minutes: u32,
    pub(crate) idle_locked: bool,
    pub(crate) items: Vec<ItemView>,
    pub(crate) last_sync: Option<SyncView>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ItemView {
    pub(crate) item_id: String,
    pub(crate) title: String,
    pub(crate) kind: String,
    pub(crate) revision: u64,
    pub(crate) deleted: bool,
    pub(crate) conflict_copy: bool,
    pub(crate) notes: String,
    pub(crate) username: Option<String>,
    pub(crate) passwords: Vec<PasswordView>,
    pub(crate) custom_fields: Vec<FieldView>,
    pub(crate) totp_code: Option<String>,
    pub(crate) totp_remaining: Option<u32>,
    pub(crate) totp_secret: Option<String>,
    pub(crate) favorite: bool,
    pub(crate) folder_id: Option<String>,
    pub(crate) folder_parent_id: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordView {
    pub(crate) name: String,
    pub(crate) password: String,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GenerateRequest {
    pub(crate) mode: String,
    pub(crate) length: u32,
    pub(crate) lowercase: bool,
    pub(crate) uppercase: bool,
    pub(crate) digits: bool,
    pub(crate) symbols: bool,
    pub(crate) avoid_ambiguous: bool,
    pub(crate) min_digits: u32,
    pub(crate) min_symbols: u32,
    pub(crate) words: u32,
    pub(crate) separator: String,
    pub(crate) capitalize: bool,
    pub(crate) include_number: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StrengthRequest {
    pub(crate) password: String,
    pub(crate) user_inputs: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StrengthView {
    pub(crate) score: u8,
    pub(crate) warning: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldView {
    pub(crate) name: String,
    pub(crate) value: String,
    pub(crate) concealed: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SyncView {
    pub(crate) pushed: usize,
    pub(crate) accepted: usize,
    pub(crate) conflicts: usize,
    pub(crate) pulled: usize,
    pub(crate) cursor: String,
}

/// Returned once. The host does not keep the recovery key after this value is built.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedVault {
    pub(crate) status: HostStatus,
    pub(crate) recovery_key: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordInput {
    name: String,
    password: String,
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FieldInput {
    name: String,
    value: String,
    concealed: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteWrite {
    pub(crate) title: String,
    pub(crate) notes: String,
    pub(crate) custom_fields: Vec<FieldInput>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginWrite {
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) passwords: Vec<PasswordInput>,
    pub(crate) notes: String,
    pub(crate) custom_fields: Vec<FieldInput>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TotpWrite {
    pub(crate) title: String,
    pub(crate) secret: String,
    pub(crate) notes: String,
    pub(crate) custom_fields: Vec<FieldInput>,
    pub(crate) folder_id: Option<String>,
    pub(crate) favorite: bool,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NoteUpdate {
    pub(crate) item_id: String,
    #[serde(flatten)]
    pub(crate) body: NoteWrite,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginUpdate {
    pub(crate) item_id: String,
    #[serde(flatten)]
    pub(crate) body: LoginWrite,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TotpUpdate {
    pub(crate) item_id: String,
    #[serde(flatten)]
    pub(crate) body: TotpWrite,
}

impl HostInner {
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, HostError> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root).map_err(|error| HostError::Store(error.to_string()))?;
        let database = root.join("vault.sqlite");
        let attachment_dir = root.join("attachments");
        let attachments = FileAttachmentStore::new(&attachment_dir)
            .map_err(|error| HostError::Store(error.to_string()))?;
        let store =
            SqliteStore::open(&database).map_err(|error| HostError::Store(error.to_string()))?;
        let idle_minutes = read_idle_minutes(&root);
        Ok(Self {
            root,
            database,
            attachment_dir,
            attachments,
            phase: Phase::Holding(store),
            last_sync: None,
            idle_limit: Duration::from_secs(u64::from(idle_minutes) * 60),
            last_activity: Instant::now(),
            idle_locked: false,
        })
    }

    pub(crate) fn lock_if_idle(&mut self) -> Result<(), HostError> {
        if !matches!(self.phase, Phase::Unlocked(_)) {
            return Ok(());
        }
        if self.last_activity.elapsed() >= self.idle_limit {
            self.lock_now(true)?;
        }
        Ok(())
    }

    pub(crate) fn status(&mut self) -> Result<HostStatus, HostError> {
        self.lock_if_idle()?;
        self.snapshot()
    }

    pub(crate) fn touch(&mut self) -> Result<HostStatus, HostError> {
        if matches!(self.phase, Phase::Unlocked(_))
            && self.last_activity.elapsed() < self.idle_limit
        {
            self.last_activity = Instant::now();
        }
        self.status()
    }

    pub(crate) fn set_idle_minutes(&mut self, minutes: u32) -> Result<HostStatus, HostError> {
        if !(MIN_IDLE_MINUTES..=MAX_IDLE_MINUTES).contains(&minutes) {
            return Err(HostError::IdleRange);
        }
        self.lock_if_idle()?;
        write_idle_minutes(&self.root, minutes)?;
        self.idle_limit = Duration::from_secs(u64::from(minutes) * 60);
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
        }
        self.snapshot()
    }

    pub(crate) fn create_vault(&mut self, password: &str) -> Result<CreatedVault, HostError> {
        if self.has_vault()? {
            return Err(HostError::AlreadyCreated);
        }
        let database = self.database.clone();
        let store = self.take_holding()?;
        match VaultSession::create(store, password) {
            Ok((session, recovery)) => {
                let recovery_key = recovery.to_text().to_string();
                drop(recovery);
                self.phase = Phase::Unlocked(Box::new(session));
                self.last_activity = Instant::now();
                self.idle_locked = false;
                Ok(CreatedVault {
                    status: self.snapshot()?,
                    recovery_key,
                })
            }
            Err(error) => {
                self.phase = Phase::Holding(reopen(&database)?);
                Err(session_err(error))
            }
        }
    }

    pub(crate) fn unlock(&mut self, password: &str) -> Result<HostStatus, HostError> {
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
            self.idle_locked = false;
            return self.snapshot();
        }
        if !self.has_vault()? {
            return Err(HostError::MissingVault);
        }
        let database = self.database.clone();
        let store = self.take_holding()?;
        match VaultSession::open(store, password) {
            Ok(session) => {
                self.phase = Phase::Unlocked(Box::new(session));
                self.last_activity = Instant::now();
                self.idle_locked = false;
                self.snapshot()
            }
            Err(error) => {
                self.phase = Phase::Holding(reopen(&database)?);
                Err(session_err(error))
            }
        }
    }

    pub(crate) fn lock(&mut self) -> Result<HostStatus, HostError> {
        self.lock_now(false)?;
        self.snapshot()
    }

    pub(crate) fn create_note(
        &mut self,
        folder_id: Option<Uuid>,
        item: &NoteWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let mut draft = ItemDraft::new(title, ItemData::SecureNote);
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        session.create_item(draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_note(
        &mut self,
        item_id: Uuid,
        folder_id: Option<Uuid>,
        item: &NoteWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let current = session.get_item(item_id).map_err(session_err)?;
        if !matches!(current.data, ItemData::SecureNote) {
            return Err(HostError::WrongKind);
        }
        let mut draft = current.content.clone();
        draft.title = title;
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        session.update_item(item_id, draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn create_login(
        &mut self,
        folder_id: Option<Uuid>,
        item: &LoginWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let passwords = login_passwords(&item.passwords)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let mut draft = ItemDraft::new(
            title,
            ItemData::Login {
                username: item.username.clone(),
                passwords,
                urls: Vec::new(),
                otp: None,
            },
        );
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        session.create_item(draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_login(
        &mut self,
        item_id: Uuid,
        folder_id: Option<Uuid>,
        item: &LoginWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let passwords = login_passwords(&item.passwords)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let current = session.get_item(item_id).map_err(session_err)?;
        if !matches!(current.data, ItemData::Login { .. }) {
            return Err(HostError::WrongKind);
        }
        let mut draft = current.content.clone();
        draft.title = title;
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        if let ItemData::Login {
            username,
            passwords: stored,
            ..
        } = &mut draft.data
        {
            *username = item.username.clone();
            *stored = passwords;
        }
        session.update_item(item_id, draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn create_totp(
        &mut self,
        folder_id: Option<Uuid>,
        item: &TotpWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let mut draft = ItemDraft::new(
            title,
            ItemData::Totp {
                totp: Totp::new(normalize_secret(&item.secret)),
            },
        );
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        session.create_item(draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_totp(
        &mut self,
        item_id: Uuid,
        folder_id: Option<Uuid>,
        item: &TotpWrite,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(&item.title)?;
        let fields = custom_fields(&item.custom_fields)?;
        self.ensure_folder(folder_id)?;
        let session = self.session()?;
        let current = session.get_item(item_id).map_err(session_err)?;
        let ItemData::Totp { totp } = &current.data else {
            return Err(HostError::WrongKind);
        };
        let mut next = totp.clone();
        next.secret = normalize_secret(&item.secret);
        let mut draft = current.content.clone();
        draft.title = title;
        draft.notes = item.notes.clone();
        draft.folder_id = folder_id;
        draft.favorite = item.favorite;
        draft.custom_fields = fields;
        draft.data = ItemData::Totp { totp: next };
        session.update_item(item_id, draft).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn create_folder(
        &mut self,
        title: &str,
        parent_id: Option<Uuid>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(title)?;
        self.session()?
            .create_folder(title, parent_id)
            .map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn update_folder(
        &mut self,
        item_id: Uuid,
        title: &str,
        parent_id: Option<Uuid>,
    ) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let title = require_title(title)?;
        self.session()?
            .update_folder(item_id, title, parent_id)
            .map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn delete_item(&mut self, item_id: Uuid) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let (is_folder, parent) = {
            let current = self.session()?.get_item(item_id).map_err(session_err)?;
            (current.is_folder(), current.folder_parent_id())
        };
        if is_folder {
            let children: Vec<(Uuid, bool, String)> = self
                .session()?
                .list_items()
                .map_err(session_err)?
                .into_iter()
                .filter(|item| item.item_id != item_id && item.folder_id == Some(item_id))
                .map(|item| (item.item_id, item.is_folder(), item.title.clone()))
                .collect();
            for (child_id, child_folder, title) in children {
                let session = self.session()?;
                if child_folder {
                    session
                        .update_folder(child_id, title, parent)
                        .map_err(session_err)?;
                } else {
                    let current = session.get_item(child_id).map_err(session_err)?;
                    let mut draft = current.content.clone();
                    draft.folder_id = parent;
                    session.update_item(child_id, draft).map_err(session_err)?;
                }
            }
        }
        self.session()?.delete_item(item_id).map_err(session_err)?;
        self.snapshot()
    }

    pub(crate) fn search(&mut self, query: &str) -> Result<Vec<ItemView>, HostError> {
        self.begin_activity()?;
        let items = self.session()?.search(query).map_err(session_err)?;
        Ok(items.into_iter().map(item_view).collect())
    }

    pub(crate) fn sync(&mut self, endpoint: &str) -> Result<HostStatus, HostError> {
        self.begin_activity()?;
        let mut transport = match HttpSyncTransport::new(endpoint.trim()) {
            Ok(transport) => transport,
            Err(HttpSyncError::Url) => return Err(HostError::BadUrl),
            Err(error) => return Err(HostError::Sync(error.to_string())),
        };
        let report = {
            let session = self.session()?;
            sync_items(session, &mut transport)
                .map_err(|error| HostError::Sync(error.to_string()))?
        };
        self.last_sync = Some(sync_view(report));
        self.snapshot()
    }

    fn begin_activity(&mut self) -> Result<(), HostError> {
        self.lock_if_idle()?;
        if matches!(self.phase, Phase::Unlocked(_)) {
            self.last_activity = Instant::now();
        }
        Ok(())
    }

    fn session(&mut self) -> Result<&mut VaultSession<SqliteStore>, HostError> {
        match &mut self.phase {
            Phase::Unlocked(session) => Ok(session.as_mut()),
            Phase::Holding(_) => Err(HostError::Locked),
            Phase::Closed => Err(HostError::Closed),
        }
    }

    fn ensure_folder(&mut self, folder_id: Option<Uuid>) -> Result<(), HostError> {
        let Some(folder_id) = folder_id else {
            return Ok(());
        };
        if folder_id.is_nil() {
            return Err(HostError::BadId);
        }
        let folder = self.session()?.get_item(folder_id).map_err(session_err)?;
        if !folder.is_folder() {
            return Err(HostError::WrongKind);
        }
        Ok(())
    }

    fn has_vault(&mut self) -> Result<bool, HostError> {
        if matches!(self.phase, Phase::Unlocked(_)) {
            return Ok(true);
        }
        if matches!(self.phase, Phase::Closed) {
            return Err(HostError::Closed);
        }
        Ok(self.holding_view()?.phase == "locked")
    }

    fn take_holding(&mut self) -> Result<SqliteStore, HostError> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Holding(store) => Ok(store),
            other => {
                let error = match &other {
                    Phase::Unlocked(_) => HostError::AlreadyCreated,
                    Phase::Closed | Phase::Holding(_) => HostError::Closed,
                };
                self.phase = other;
                Err(error)
            }
        }
    }

    fn lock_now(&mut self, idle: bool) -> Result<(), HostError> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Unlocked(session) => {
                self.phase = Phase::Holding((*session).into_store());
                self.idle_locked = idle;
                Ok(())
            }
            other => {
                self.phase = other;
                Err(HostError::NotUnlocked)
            }
        }
    }

    fn snapshot(&mut self) -> Result<HostStatus, HostError> {
        let _driver = &self.attachments;
        let (phase, vault_id, device_id, items) = match &mut self.phase {
            Phase::Closed => return Err(HostError::Closed),
            Phase::Unlocked(session) => {
                let items = session.list_items().map_err(session_err)?;
                (
                    "unlocked",
                    Some(session.vault().vault_id().to_string()),
                    Some(session.device_id().to_string()),
                    items.into_iter().map(item_view).collect(),
                )
            }
            Phase::Holding(store) => {
                let holding = inspect_holding(store)?;
                (
                    holding.phase,
                    holding.vault_id,
                    holding.device_id,
                    Vec::new(),
                )
            }
        };
        Ok(HostStatus {
            root: self.root.display().to_string(),
            database_path: self.database.display().to_string(),
            attachment_dir: self.attachment_dir.display().to_string(),
            phase: phase.to_string(),
            vault_id,
            device_id,
            idle_minutes: self.idle_minutes(),
            idle_locked: self.idle_locked,
            items,
            last_sync: self.last_sync.clone(),
        })
    }

    fn holding_view(&mut self) -> Result<HoldingView, HostError> {
        match &mut self.phase {
            Phase::Holding(store) => inspect_holding(store),
            Phase::Unlocked(_) => Ok(HoldingView {
                phase: "locked",
                vault_id: None,
                device_id: None,
            }),
            Phase::Closed => Err(HostError::Closed),
        }
    }

    fn idle_minutes(&self) -> u32 {
        u32::try_from(self.idle_limit.as_secs() / 60).unwrap_or(DEFAULT_IDLE_MINUTES)
    }
}

struct HoldingView {
    phase: &'static str,
    vault_id: Option<String>,
    device_id: Option<String>,
}

pub(crate) fn generated_secret(request: &GenerateRequest) -> Result<String, HostError> {
    let secret = if request.mode == "passphrase" {
        generate_passphrase(&PassphraseOptions {
            words: usize::try_from(request.words).unwrap_or(usize::MAX),
            separator: request.separator.clone(),
            capitalize: request.capitalize,
            include_number: request.include_number,
        })
    } else if request.mode == "password" {
        generate_password(&PasswordOptions {
            length: usize::try_from(request.length).unwrap_or(usize::MAX),
            lowercase: request.lowercase,
            uppercase: request.uppercase,
            digits: request.digits,
            symbols: request.symbols,
            avoid_ambiguous: request.avoid_ambiguous,
            min_digits: usize::try_from(request.min_digits).unwrap_or(usize::MAX),
            min_symbols: usize::try_from(request.min_symbols).unwrap_or(usize::MAX),
        })
    } else {
        return Err(HostError::UnknownGenerator);
    };
    secret
        .map(|value| value.to_string())
        .map_err(|error| HostError::Protocol(explain(error)))
}

pub(crate) fn measured_strength(password: &str, user_inputs: &[String]) -> StrengthView {
    let inputs: Vec<&str> = user_inputs.iter().map(String::as_str).collect();
    let strength = password_strength(password, &inputs);
    StrengthView {
        score: strength.score,
        warning: strength.warning,
    }
}

fn require_title(title: &str) -> Result<String, HostError> {
    let title = title.trim();
    if title.is_empty() {
        Err(HostError::EmptyTitle)
    } else {
        Ok(title.to_string())
    }
}

fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(|character| character.to_uppercase())
        .collect()
}

fn login_passwords(passwords: &[PasswordInput]) -> Result<Vec<LoginPassword>, HostError> {
    for password in passwords {
        if password.name.trim().is_empty() {
            return Err(HostError::EmptyPasswordName);
        }
    }
    Ok(passwords
        .iter()
        .map(|password| LoginPassword {
            name: password.name.clone(),
            password: password.password.clone(),
        })
        .collect())
}

fn custom_fields(fields: &[FieldInput]) -> Result<Vec<CustomField>, HostError> {
    for field in fields {
        if field.name.trim().is_empty() {
            return Err(HostError::EmptyFieldName);
        }
    }
    Ok(fields
        .iter()
        .map(|field| CustomField {
            name: field.name.clone(),
            value: field.value.clone(),
            concealed: field.concealed,
        })
        .collect())
}

fn item_view(item: Item) -> ItemView {
    let now = unix_now();
    let period = item.totp_period();
    let totp_code = item
        .totp_code_at(now)
        .ok()
        .flatten()
        .map(|code| code.to_string());
    let totp_remaining = match (totp_code.as_ref(), period) {
        (Some(_), Some(period)) if period > 0 => {
            let elapsed = u32::try_from(now % u64::from(period)).unwrap_or(0);
            Some(period - elapsed)
        }
        _ => None,
    };
    ItemView {
        item_id: item.item_id.to_string(),
        title: item.title.clone(),
        kind: kind_label(&item.data).to_string(),
        revision: item.revision,
        deleted: item.deleted,
        conflict_copy: item.title.starts_with("冲突 "),
        notes: item.notes.clone(),
        username: item.login_username().map(ToOwned::to_owned),
        passwords: item
            .login_passwords()
            .unwrap_or(&[])
            .iter()
            .map(|password| PasswordView {
                name: password.name.clone(),
                password: password.password.clone(),
            })
            .collect(),
        custom_fields: item
            .custom_fields
            .iter()
            .map(|field| FieldView {
                name: field.name.clone(),
                value: field.value.clone(),
                concealed: field.concealed,
            })
            .collect(),
        totp_code,
        totp_remaining,
        totp_secret: item.totp_secret().map(ToOwned::to_owned),
        favorite: item.favorite,
        folder_id: item.folder_id.map(|id| id.to_string()),
        folder_parent_id: item.folder_parent_id().map(|id| id.to_string()),
    }
}

fn kind_label(data: &ItemData) -> &'static str {
    match data {
        ItemData::Login { .. } => "登录",
        ItemData::SecureNote => "笔记",
        ItemData::Folder { .. } => "文件夹",
        ItemData::Totp { .. } => "验证码",
        ItemData::Hotp { .. } => "计数验证码",
        ItemData::Card { .. } => "银行卡",
        ItemData::Identity { .. } => "身份",
    }
}

fn sync_view(report: SyncReport) -> SyncView {
    SyncView {
        pushed: report.pushed,
        accepted: report.accepted,
        conflicts: report.conflicts,
        pulled: report.pulled,
        cursor: report.cursor.as_str().to_string(),
    }
}

fn inspect_holding(store: &mut SqliteStore) -> Result<HoldingView, HostError> {
    let transaction = store
        .begin()
        .map_err(|error| HostError::Store(error.to_string()))?;
    let ids = transaction
        .list_vault_ids()
        .map_err(|error| HostError::Store(error.to_string()))?;
    let view = if ids.is_empty() {
        HoldingView {
            phase: "empty",
            vault_id: None,
            device_id: None,
        }
    } else if ids.len() == 1 {
        let vault_id = ids[0];
        let device_id = transaction
            .local_device_id(vault_id)
            .map_err(|error| HostError::Store(error.to_string()))?
            .map(|value| value.to_string());
        HoldingView {
            phase: "locked",
            vault_id: Some(vault_id.to_string()),
            device_id,
        }
    } else {
        let _ = transaction.rollback();
        return Err(HostError::VaultCount);
    };
    transaction
        .rollback()
        .map_err(|error| HostError::Store(error.to_string()))?;
    Ok(view)
}

fn read_idle_minutes(root: &Path) -> u32 {
    let text = std::fs::read_to_string(root.join("idle-minutes")).unwrap_or_default();
    text.trim()
        .parse::<u32>()
        .ok()
        .map(|minutes| minutes.clamp(MIN_IDLE_MINUTES, MAX_IDLE_MINUTES))
        .unwrap_or(DEFAULT_IDLE_MINUTES)
}

fn write_idle_minutes(root: &Path, minutes: u32) -> Result<(), HostError> {
    std::fs::write(root.join("idle-minutes"), format!("{minutes}\n"))
        .map_err(|error| HostError::Store(error.to_string()))
}

fn reopen(path: &Path) -> Result<SqliteStore, HostError> {
    SqliteStore::open(path).map_err(|error| HostError::Store(error.to_string()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn session_err(error: SessionError<SqliteStoreError>) -> HostError {
    match error {
        SessionError::Store(error) => HostError::Store(error.to_string()),
        SessionError::Core(error) => HostError::Protocol(explain(error)),
        SessionError::VaultCount => HostError::VaultCount,
        other => HostError::Protocol(other.to_string()),
    }
}

fn explain(error: vault_core::Error) -> String {
    use vault_core::{Error, InputError};
    match error {
        Error::UnlockFailed => "主密码不正确".to_string(),
        Error::NotFound => "找不到这条条目".to_string(),
        Error::InvalidInput(InputError::EmptyTitle) => "标题不能是空白".to_string(),
        Error::InvalidInput(InputError::EmptyPassword) => "主密码不能是空白".to_string(),
        Error::InvalidInput(InputError::InvalidPasswordLength { min, max }) => {
            format!("密码长度必须在 {min} 到 {max} 之间")
        }
        Error::InvalidInput(InputError::NoCharacterGroups) => "至少要包含一类字符".to_string(),
        Error::InvalidInput(InputError::InvalidTotpSecretEncoding) => {
            "验证码密钥必须是不带填充的 Base32".to_string()
        }
        Error::InvalidInput(InputError::TotpSecretTooShort { min_bits }) => {
            format!("验证码密钥太短，至少需要 {min_bits} 位")
        }
        Error::InvalidInput(InputError::NotTotp) => "这条不是验证码条目".to_string(),
        Error::InvalidInput(InputError::NotLoginItem) => "这条不是登录条目".to_string(),
        Error::InvalidInput(InputError::NotFolder) => "这条不是文件夹".to_string(),
        Error::InvalidInput(InputError::FolderCycle) => "文件夹不能放到自己里面".to_string(),
        Error::InvalidInput(InputError::DeletedItem) => "这条已经删除".to_string(),
        Error::InvalidInput(InputError::InvalidFolderId) => "文件夹编号无效".to_string(),
        Error::InvalidInput(other) => other.to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_lock_drops_the_vault_key_until_the_master_password() {
        let root = std::env::temp_dir().join(format!(
            "citripass-ui-desktop-idle-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = HostInner::open(&root).unwrap();
        let created = host.create_vault("idle-test-password").unwrap();
        assert_eq!(created.status.phase, "unlocked");
        assert!(!created.recovery_key.trim().is_empty());
        drop(created);
        host.create_note(
            None,
            &NoteWrite {
                title: "Hello".to_string(),
                notes: "body".to_string(),
                custom_fields: Vec::new(),
                folder_id: None,
                favorite: false,
            },
        )
        .unwrap();
        host.idle_limit = Duration::from_millis(1);
        host.last_activity = Instant::now() - Duration::from_secs(5);
        let locked = host.status().unwrap();
        assert_eq!(locked.phase, "locked");
        assert!(locked.idle_locked);
        assert!(locked.items.is_empty());
        match host.create_note(
            None,
            &NoteWrite {
                title: "Later".to_string(),
                notes: String::new(),
                custom_fields: Vec::new(),
                folder_id: None,
                favorite: false,
            },
        ) {
            Err(HostError::Locked) => {}
            Err(error) => panic!("expected the idle lock to reject the note: {error}"),
            Ok(_) => panic!("expected the idle lock to reject the note"),
        }
        let unlocked = host.unlock("idle-test-password").unwrap();
        assert_eq!(unlocked.phase, "unlocked");
        assert!(!unlocked.idle_locked);
        assert_eq!(unlocked.items.len(), 1);
        assert_eq!(unlocked.items[0].title, "Hello");
        host.idle_limit = Duration::from_secs(300);
        host.set_idle_minutes(12).unwrap();
        drop(host);
        let reopened = HostInner::open(&root).unwrap();
        assert_eq!(reopened.idle_minutes(), 12);
        drop(reopened);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_save_keeps_passwords_custom_fields_and_totp_parameters() {
        use vault_core::TotpAlgorithm;

        let root = std::env::temp_dir().join(format!(
            "citripass-ui-desktop-fields-{}-{}",
            std::process::id(),
            unix_now()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let mut host = HostInner::open(&root).unwrap();
        host.create_vault("fields-test-password").unwrap();
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        host.create_login(
            None,
            &LoginWrite {
                title: "Mail".to_string(),
                username: "ada".to_string(),
                passwords: vec![
                    PasswordInput {
                        name: "密码".to_string(),
                        password: "one".to_string(),
                    },
                    PasswordInput {
                        name: "备用".to_string(),
                        password: "two".to_string(),
                    },
                ],
                notes: "desk".to_string(),
                custom_fields: vec![FieldInput {
                    name: "PIN".to_string(),
                    value: "1234".to_string(),
                    concealed: true,
                }],
                folder_id: None,
                favorite: true,
            },
        )
        .unwrap();
        let created = host.status().unwrap();
        let login = created
            .items
            .iter()
            .find(|item| item.title == "Mail")
            .unwrap();
        assert_eq!(login.revision, 1);
        assert_eq!(login.passwords.len(), 2);
        assert_eq!(login.passwords[1].name, "备用");
        assert_eq!(login.custom_fields.len(), 1);
        let login_id = uuid::Uuid::parse_str(&login.item_id).unwrap();

        host.create_totp(
            None,
            &TotpWrite {
                title: "Door".to_string(),
                secret: secret.to_string(),
                notes: String::new(),
                custom_fields: vec![FieldInput {
                    name: "位置".to_string(),
                    value: "大门".to_string(),
                    concealed: false,
                }],
                folder_id: None,
                favorite: false,
            },
        )
        .unwrap();
        let totp_id = {
            let session = host.session().unwrap();
            let item = session
                .list_items()
                .unwrap()
                .into_iter()
                .find(|item| item.title == "Door")
                .unwrap();
            let mut draft = item.content.clone();
            if let ItemData::Totp { totp } = &mut draft.data {
                totp.algorithm = TotpAlgorithm::Sha256;
                totp.digits = 8;
                totp.period = 45;
            }
            session.update_item(item.item_id, draft).unwrap();
            item.item_id
        };

        host.update_login(
            login_id,
            None,
            &LoginWrite {
                title: "Mail".to_string(),
                username: "ada".to_string(),
                passwords: vec![
                    PasswordInput {
                        name: "密码".to_string(),
                        password: "one".to_string(),
                    },
                    PasswordInput {
                        name: "备用".to_string(),
                        password: "two".to_string(),
                    },
                    PasswordInput {
                        name: "应用".to_string(),
                        password: String::new(),
                    },
                ],
                notes: "desk".to_string(),
                custom_fields: vec![FieldInput {
                    name: "PIN".to_string(),
                    value: "1234".to_string(),
                    concealed: true,
                }],
                folder_id: None,
                favorite: true,
            },
        )
        .unwrap();
        host.update_totp(
            totp_id,
            None,
            &TotpWrite {
                title: "Door".to_string(),
                secret: secret.to_string(),
                notes: "kept".to_string(),
                custom_fields: vec![FieldInput {
                    name: "位置".to_string(),
                    value: "侧门".to_string(),
                    concealed: false,
                }],
                folder_id: None,
                favorite: false,
            },
        )
        .unwrap();

        let status = host.status().unwrap();
        let login = status
            .items
            .iter()
            .find(|item| item.title == "Mail")
            .unwrap();
        assert_eq!(login.revision, 2);
        assert_eq!(login.passwords.len(), 3);
        assert_eq!(login.passwords[2].password, "");
        assert_eq!(login.custom_fields[0].value, "1234");
        let door = status
            .items
            .iter()
            .find(|item| item.title == "Door")
            .unwrap();
        assert_eq!(door.custom_fields[0].value, "侧门");
        assert_eq!(door.notes, "kept");
        let stored = host.session().unwrap().get_item(totp_id).unwrap();
        match &stored.data {
            ItemData::Totp { totp } => {
                assert_eq!(totp.secret, secret);
                assert_eq!(totp.algorithm, TotpAlgorithm::Sha256);
                assert_eq!(totp.digits, 8);
                assert_eq!(totp.period, 45);
            }
            _ => panic!("totp"),
        }
        drop(host);
        let _ = std::fs::remove_dir_all(&root);
    }
}
