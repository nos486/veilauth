import { create } from "zustand";
import type { VaultToken } from "../lib/tokens";

export type Phase = "loading" | "welcome" | "signup" | "login" | "locked" | "unlocked";
export type Screen =
  | { name: "vault" }
  | { name: "add" }
  | { name: "edit"; id: string }
  | { name: "trash" }
  | { name: "settings" }
  | { name: "about" };

export type Notice =
  "signedOut" | "sessionEnded" | "passwordChanged" | "accountDeleted" | "locked" | null;

export type SyncStatus = "idle" | "syncing" | "offline" | "error";

export interface AppState {
  phase: Phase;
  screen: Screen;
  email: string;
  notice: Notice;
  turnstileSiteKey: string | null;
  updateReady: boolean;
  tokens: VaultToken[];
  /** items that failed to decrypt or validate; shown as a warning, never silently dropped */
  unreadable: number;
  sync: SyncStatus;
  lastSyncAt: number | null;
  conflictsResolved: number;
  /** the server sent older versions of items than this device had seen */
  rollbackDetected: boolean;
}

export const initialAppState: AppState = {
  phase: "loading",
  screen: { name: "vault" },
  email: "",
  notice: null,
  turnstileSiteKey: null,
  updateReady: false,
  tokens: [],
  unreadable: 0,
  sync: "idle",
  lastSyncAt: null,
  conflictsResolved: 0,
  rollbackDetected: false,
};

/** In-memory UI state. Decrypted tokens live only here and are dropped on lock. */
export const useApp = create<AppState>()(() => ({ ...initialAppState }));

export function navigate(screen: Screen): void {
  useApp.setState({ screen });
}
