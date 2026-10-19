mod host;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::Manager;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::host::{
    CreatedVault, GenerateRequest, HostInner, HostStatus, ItemView, LoginUpdate, LoginWrite,
    NoteUpdate, NoteWrite, StrengthRequest, StrengthView, SyncAuthRequest, TotpUpdate, TotpWrite,
};

struct SharedHost(Arc<Mutex<HostInner>>);

struct Secret(String);

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    fn expose(&self) -> &str {
        &self.0
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let directory = app.path().app_data_dir()?;
            let host = HostInner::open(directory).map_err(|error| error.to_string())?;
            let shared = Arc::new(Mutex::new(host));
            let watcher = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("citripass-autolock".to_string())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let mut host = lock_arc(&watcher);
                    let _ = host.lock_if_idle();
                })
                .map_err(|error| error.to_string())?;
            app.manage(SharedHost(shared));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            unlock_vault,
            lock_vault,
            touch_vault,
            set_idle_minutes,
            create_note,
            update_note,
            create_login,
            update_login,
            create_totp,
            update_totp,
            create_folder,
            update_folder,
            delete_item,
            search_items,
            sync_vault,
            sync_register,
            sync_login,
            sync_logout,
            generate_password,
            password_strength
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

async fn blocking<T, F>(action: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(action)
        .await
        .map_err(|error| format!("宿主任务中断：{error}"))?
}

fn optional_id(value: Option<String>) -> Result<Option<Uuid>, String> {
    match value {
        Some(text) if !text.trim().is_empty() => Uuid::parse_str(text.trim())
            .map(Some)
            .map_err(|_| "条目编号无法识别".to_string()),
        _ => Ok(None),
    }
}

fn required_id(value: String) -> Result<Uuid, String> {
    Uuid::parse_str(value.trim()).map_err(|_| "条目编号无法识别".to_string())
}

#[tauri::command]
async fn vault_status(host: State<'_, SharedHost>) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .status()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_vault(
    host: State<'_, SharedHost>,
    password: String,
) -> Result<CreatedVault, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        lock_arc(&shared)
            .create_vault(secret.expose())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn unlock_vault(host: State<'_, SharedHost>, password: String) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    blocking(move || {
        lock_arc(&shared)
            .unlock(secret.expose())
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn lock_vault(host: State<'_, SharedHost>) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || lock_arc(&shared).lock().map_err(|error| error.to_string())).await
}

#[tauri::command]
async fn touch_vault(host: State<'_, SharedHost>) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || lock_arc(&shared).touch().map_err(|error| error.to_string())).await
}

#[tauri::command]
async fn set_idle_minutes(host: State<'_, SharedHost>, minutes: u32) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .set_idle_minutes(minutes)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_note(
    host: State<'_, SharedHost>,
    mut body: NoteWrite,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let folder_id = optional_id(body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .create_note(folder_id, &body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_note(
    host: State<'_, SharedHost>,
    mut body: NoteUpdate,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(std::mem::take(&mut body.item_id))?;
    let folder_id = optional_id(body.body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .update_note(item_id, folder_id, &body.body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_login(
    host: State<'_, SharedHost>,
    mut body: LoginWrite,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let folder_id = optional_id(body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .create_login(folder_id, &body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_login(
    host: State<'_, SharedHost>,
    mut body: LoginUpdate,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(std::mem::take(&mut body.item_id))?;
    let folder_id = optional_id(body.body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .update_login(item_id, folder_id, &body.body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_totp(
    host: State<'_, SharedHost>,
    mut body: TotpWrite,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let folder_id = optional_id(body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .create_totp(folder_id, &body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_totp(
    host: State<'_, SharedHost>,
    mut body: TotpUpdate,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(std::mem::take(&mut body.item_id))?;
    let folder_id = optional_id(body.body.folder_id.take())?;
    blocking(move || {
        lock_arc(&shared)
            .update_totp(item_id, folder_id, &body.body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_folder(
    host: State<'_, SharedHost>,
    title: String,
    parent_id: Option<String>,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let parent_id = optional_id(parent_id)?;
    blocking(move || {
        lock_arc(&shared)
            .create_folder(&title, parent_id)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_folder(
    host: State<'_, SharedHost>,
    item_id: String,
    title: String,
    parent_id: Option<String>,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(item_id)?;
    let parent_id = optional_id(parent_id)?;
    blocking(move || {
        lock_arc(&shared)
            .update_folder(item_id, &title, parent_id)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn delete_item(host: State<'_, SharedHost>, item_id: String) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(item_id)?;
    blocking(move || {
        lock_arc(&shared)
            .delete_item(item_id)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn search_items(host: State<'_, SharedHost>, query: String) -> Result<Vec<ItemView>, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .search(&query)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn sync_vault(host: State<'_, SharedHost>, endpoint: String) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .sync(&endpoint)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn sync_register(
    host: State<'_, SharedHost>,
    body: SyncAuthRequest,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .sync_register(&body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn sync_login(
    host: State<'_, SharedHost>,
    body: SyncAuthRequest,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .sync_login(&body)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn sync_logout(host: State<'_, SharedHost>) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    blocking(move || {
        lock_arc(&shared)
            .sync_logout()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
fn generate_password(options: GenerateRequest) -> Result<String, String> {
    host::generated_secret(&options).map_err(|error| error.to_string())
}

#[tauri::command]
fn password_strength(body: StrengthRequest) -> StrengthView {
    host::measured_strength(&body.password, &body.user_inputs)
}

fn lock_arc(host: &Arc<Mutex<HostInner>>) -> std::sync::MutexGuard<'_, HostInner> {
    host.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
