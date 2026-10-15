import { invoke } from "@tauri-apps/api/core";

export type Phase = "empty" | "locked" | "unlocked";

export interface ItemView {
  itemId: string;
  title: string;
  kind: string;
  revision: number;
  deleted: boolean;
  conflictCopy: boolean;
  notes: string;
  username: string | null;
  password: string | null;
  totpCode: string | null;
  totpRemaining: number | null;
  totpSecret: string | null;
  favorite: boolean;
  folderId: string | null;
  folderParentId: string | null;
}

export interface SyncView {
  pushed: number;
  accepted: number;
  conflicts: number;
  pulled: number;
  cursor: string;
}

export interface HostStatus {
  root: string;
  databasePath: string;
  attachmentDir: string;
  phase: Phase;
  vaultId: string | null;
  deviceId: string | null;
  idleMinutes: number;
  idleLocked: boolean;
  items: ItemView[];
  lastSync: SyncView | null;
}

export interface CreatedVault {
  status: HostStatus;
  recoveryKey: string;
}

export function inDesktop(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function vaultStatus(): Promise<HostStatus> {
  return invoke("vault_status");
}

export function createVault(password: string): Promise<CreatedVault> {
  return invoke("create_vault", { password });
}

export function unlockVault(password: string): Promise<HostStatus> {
  return invoke("unlock_vault", { password });
}

export function lockVault(): Promise<HostStatus> {
  return invoke("lock_vault");
}

export function touchVault(): Promise<HostStatus> {
  return invoke("touch_vault");
}

export function setIdleMinutes(minutes: number): Promise<HostStatus> {
  return invoke("set_idle_minutes", { minutes });
}

export function createNote(
  title: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("create_note", { title, notes, folderId, favorite });
}

export function updateNote(
  itemId: string,
  title: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("update_note", { itemId, title, notes, folderId, favorite });
}

export function createLogin(
  title: string,
  username: string,
  password: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("create_login", { title, username, password, notes, folderId, favorite });
}

export function updateLogin(
  itemId: string,
  title: string,
  username: string,
  password: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("update_login", {
    itemId,
    title,
    username,
    password,
    notes,
    folderId,
    favorite,
  });
}

export function createTotp(
  title: string,
  secret: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("create_totp", { title, secret, notes, folderId, favorite });
}

export function updateTotp(
  itemId: string,
  title: string,
  secret: string,
  notes: string,
  folderId: string | null,
  favorite: boolean,
): Promise<HostStatus> {
  return invoke("update_totp", { itemId, title, secret, notes, folderId, favorite });
}

export function createFolder(title: string, parentId: string | null): Promise<HostStatus> {
  return invoke("create_folder", { title, parentId });
}

export function updateFolder(
  itemId: string,
  title: string,
  parentId: string | null,
): Promise<HostStatus> {
  return invoke("update_folder", { itemId, title, parentId });
}

export function deleteItem(itemId: string): Promise<HostStatus> {
  return invoke("delete_item", { itemId });
}

export function searchItems(query: string): Promise<ItemView[]> {
  return invoke("search_items", { query });
}

export function syncVault(endpoint: string): Promise<HostStatus> {
  return invoke("sync_vault", { endpoint });
}

export function generatePassword(length: number): Promise<string> {
  return invoke("generate_password", { length });
}

export function errorText(error: unknown): string {
  if (typeof error === "string" && error.trim()) {
    return error;
  }
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return "操作没有完成";
}
