mod host;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tauri::Manager;
use tauri::State;
use uuid::Uuid;
use zeroize::Zeroize;

use crate::host::{CreatedVault, HostInner, HostStatus, ItemView, LoginItem, TextItem, TotpItem};

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
            generate_password
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
    title: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .create_note(TextItem {
                title: &title,
                notes: &notes,
                folder_id,
                favorite,
            })
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_note(
    host: State<'_, SharedHost>,
    item_id: String,
    title: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let item_id = required_id(item_id)?;
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .update_note(
                item_id,
                TextItem {
                    title: &title,
                    notes: &notes,
                    folder_id,
                    favorite,
                },
            )
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_login(
    host: State<'_, SharedHost>,
    title: String,
    username: String,
    password: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .create_login(LoginItem {
                title: &title,
                username: &username,
                password: secret.expose(),
                notes: &notes,
                folder_id,
                favorite,
            })
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn update_login(
    host: State<'_, SharedHost>,
    item_id: String,
    title: String,
    username: String,
    password: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let secret = Secret(password);
    let item_id = required_id(item_id)?;
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .update_login(
                item_id,
                LoginItem {
                    title: &title,
                    username: &username,
                    password: secret.expose(),
                    notes: &notes,
                    folder_id,
                    favorite,
                },
            )
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn create_totp(
    host: State<'_, SharedHost>,
    title: String,
    secret: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let hidden = Secret(secret);
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .create_totp(TotpItem {
                title: &title,
                secret: hidden.expose(),
                notes: &notes,
                folder_id,
                favorite,
            })
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
async fn update_totp(
    host: State<'_, SharedHost>,
    item_id: String,
    title: String,
    secret: String,
    notes: String,
    folder_id: Option<String>,
    favorite: bool,
) -> Result<HostStatus, String> {
    let shared = Arc::clone(&host.0);
    let hidden = Secret(secret);
    let item_id = required_id(item_id)?;
    let folder_id = optional_id(folder_id)?;
    blocking(move || {
        lock_arc(&shared)
            .update_totp(
                item_id,
                TotpItem {
                    title: &title,
                    secret: hidden.expose(),
                    notes: &notes,
                    folder_id,
                    favorite,
                },
            )
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
fn generate_password(length: u32) -> Result<String, String> {
    host::generated_password(length).map_err(|error| error.to_string())
}

fn lock_arc(host: &Arc<Mutex<HostInner>>) -> std::sync::MutexGuard<'_, HostInner> {
    host.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
