import { invoke } from "@tauri-apps/api/core";

export type Phase = "empty" | "locked" | "unlocked";

export interface ItemView {
  itemId: string;
  title: string;
  kind: string;
  revision: number;
  deleted: boolean;
  conflictCopy: boolean;
}

export interface SyncView {
  pushed: number;
  accepted: number;
  conflicts: number;
  pulled: number;
  cursor: string;
}

export interface DeviceView {
  id: string;
  databasePath: string;
  attachmentDir: string;
  phase: Phase;
  vaultId: string | null;
  deviceId: string | null;
  items: ItemView[];
  lastSync: SyncView | null;
}

export interface HostStatus {
  root: string;
  devices: DeviceView[];
}

export function inDesktopHost(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function hostStatus(): Promise<HostStatus> {
  return invoke("host_status");
}

export function createDeviceA(password: string): Promise<HostStatus> {
  return invoke("create_device_a", { password });
}

export function unlockDevice(device: string, password: string): Promise<HostStatus> {
  return invoke("unlock_device", { device, password });
}

export function provisionDeviceB(password: string): Promise<HostStatus> {
  return invoke("provision_device_b", { password });
}

export function createNote(device: string, title: string, notes: string): Promise<HostStatus> {
  return invoke("create_note", { device, title, notes });
}

export function renameItem(device: string, itemId: string, title: string): Promise<HostStatus> {
  return invoke("rename_item", { device, itemId, title });
}

export function syncDevice(device: string, endpoint: string): Promise<HostStatus> {
  return invoke("sync_device", { device, endpoint });
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
