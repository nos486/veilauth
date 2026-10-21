import type { TokenItem } from "@zk2fa/crypto";
import type { SessionResponse } from "@zk2fa/shared";
import { ApiClient, ApiError, type WithLock } from "../api/client";
import type { CryptoClient } from "../crypto/client";
import type { RegistrationKeys } from "../crypto/protocol";
import { clearClipboard } from "../lib/clipboard";
import { compareTokens, TRASH_RETENTION_MS, type VaultToken } from "../lib/tokens";
import { uuidv7 } from "../lib/uuid";
import { initialAppState, type Notice, useApp } from "../store/app";
import type { LocalStore, StoredSession } from "../store/db";
import { SyncEngine } from "../sync/engine";

export class UserError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "UserError";
    this.code = code;
  }
}

interface PendingSignup {
  userId: string;
  email: string;
  keys: RegistrationKeys;
}

const SYNC_INTERVAL_MS = 60_000;
const LOCAL_CHANGE_DEBOUNCE_MS = 500;

/**
 * Glue between the UI, the crypto worker, the API and the offline store. Holds no secrets itself:
 * the vault key is in the worker, decrypted tokens are in the in-memory UI store.
 */
export class VaultController {
  readonly api: ApiClient;
  private session: StoredSession | null = null;
  private engine: SyncEngine | null = null;
  private signup: PendingSignup | null = null;
  /** blob → decrypted token, so a sync only decrypts what changed */
  private plainCache = new Map<string, { blob: string; token: VaultToken | null }>();
  private syncTimer: ReturnType<typeof setInterval> | undefined;
  private changeTimer: ReturnType<typeof setTimeout> | undefined;
  /** applied on the next lock (docs/DECISIONS.md D-018) */
  private applyUpdate: (() => void) | null = null;

  constructor(
    private readonly crypto: CryptoClient,
    private readonly store: LocalStore,
    options: { fetch?: typeof fetch; baseUrl?: string; withLock?: WithLock } = {},
  ) {
    this.api = new ApiClient({
      ...(options.fetch ? { fetch: options.fetch } : {}),
      ...(options.baseUrl !== undefined ? { baseUrl: options.baseUrl } : {}),
      ...(options.withLock ? { withLock: options.withLock } : {}),
      tokens: {
        loadRefreshToken: async () => (await this.store.getSession())?.refreshToken ?? null,
        saveRefreshToken: async (token) => {
          await this.store.updateSession({ refreshToken: token });
          if (this.session) this.session = { ...this.session, refreshToken: token };
        },
      },
      onSessionEnded: () => {
        void this.sessionEnded();
      },
    });
  }

  // ------------------------------------------------------------------ startup

  async boot(): Promise<void> {
    this.session = await this.store.getSession();
    const s = this.session;
    if (s === null) useApp.setState({ phase: "welcome" });
    else if (s.refreshToken === null) useApp.setState({ phase: "login", email: s.email });
    else useApp.setState({ phase: "locked", email: s.email });
    void this.loadConfig();
  }

  private async loadConfig(): Promise<void> {
    try {
      const [config] = await Promise.all([this.api.config(), this.api.time()]);
      useApp.setState({ turnstileSiteKey: config.turnstileSiteKey });
    } catch (e: unknown) {
      // Offline start: unlock still works from the cache; the config is fetched again on sync.
      if (!(e instanceof ApiError)) throw e;
    }
  }

  // ------------------------------------------------------------------ sign up

  /** Step 1: derive all keys (Argon2id in the worker). Returns the recovery words to show. */
  async beginSignup(email: string, password: string): Promise<string> {
    const userId = uuidv7();
    const keys = await this.crypto.call("register", { password, userId });
    this.signup = { userId, email: email.trim(), keys };
    return keys.mnemonic;
  }

  cancelSignup(): void {
    this.signup = null;
    void this.crypto.call("lock", {});
  }

  /** Step 2 (after the user proved they saved the words): create the account on the server. */
  async completeSignup(turnstileToken: string | null): Promise<void> {
    const p = this.signup;
    if (!p) throw new UserError("SIGNUP_EXPIRED");
    const deviceId = uuidv7();
    const session = await this.api.register({
      userId: p.userId,
      email: p.email,
      kdf: p.keys.kdf,
      authKey: p.keys.authKey,
      wrappedVaultKey: p.keys.wrappedVaultKey,
      recovery: p.keys.recovery,
      device: { id: deviceId, platform: "web", nameEnc: null },
      ...(turnstileToken !== null ? { turnstileToken } : {}),
    });
    this.signup = null;
    await this.store.wipe();
    await this.adoptSession(p.email, session);
    await this.enterVault();
  }

  // ------------------------------------------------------------------ log in / unlock / lock

  async login(email: string, password: string, turnstileToken: string | null): Promise<void> {
    const normalized = email.trim();
    const { kdf } = await this.api.prelogin(normalized);
    const { authKey } = await this.crypto.call("deriveLogin", { password, kdf });
    const session = await this.api.login({
      email: normalized,
      authKey,
      device: { id: uuidv7(), platform: "web", nameEnc: null },
      ...(turnstileToken !== null ? { turnstileToken } : {}),
    });
    await this.crypto.call("unlock", {
      userId: session.userId,
      wrappedVaultKey: session.wrappedVaultKey,
    });
    const previous = await this.store.getSession();
    // A different account on this browser: never mix caches.
    if (previous?.userId !== session.userId) await this.store.wipe();
    await this.adoptSession(normalized, session);
    await this.enterVault();
  }

  /** Unlocks from the offline cache; falls back to an online login if the cached wrap is stale. */
  async unlock(password: string): Promise<void> {
    const s = this.session;
    if (!s) throw new UserError("NO_SESSION");
    const res = await this.crypto.call("unlockWithPassword", {
      password,
      kdf: s.kdf,
      userId: s.userId,
      wrappedVaultKey: s.wrappedVaultKey,
    });
    if (res.unlocked) {
      await this.enterVault();
      return;
    }
    // Wrong password, or the password was changed on another device. Ask the server.
    try {
      await this.login(s.email, password, null);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.code === "NETWORK") throw new UserError("WRONG_PASSWORD");
      throw e;
    }
  }

  async lock(notice: Notice = null): Promise<void> {
    this.stopTimers();
    this.engine = null;
    this.plainCache.clear();
    this.api.clearAccessToken();
    await this.crypto.call("lock", {});
    await clearClipboard();
    const s = this.session;
    useApp.setState({
      ...initialAppState,
      phase: s === null ? "welcome" : s.refreshToken === null ? "login" : "locked",
      email: s?.email ?? "",
      notice,
      turnstileSiteKey: useApp.getState().turnstileSiteKey,
      updateReady: useApp.getState().updateReady,
    });
    const apply = this.applyUpdate;
    if (apply) apply();
  }

  async logout(): Promise<void> {
    try {
      await this.api.logout();
    } catch (e: unknown) {
      // Offline or already revoked: the local wipe below still signs this browser out.
      if (!(e instanceof ApiError)) throw e;
    }
    await this.store.wipe();
    this.session = null;
    await this.lock("signedOut");
  }

  /** Called by the API client when the server says the session is over (revoked, password changed). */
  private async sessionEnded(): Promise<void> {
    if (this.session?.refreshToken === null) return;
    // Keep the encrypted cache and unsynced edits: logging in again as the same user pushes them.
    await this.store.updateSession({ refreshToken: null });
    if (this.session) this.session = { ...this.session, refreshToken: null };
    await this.lock("sessionEnded");
  }

  private async adoptSession(email: string, res: SessionResponse): Promise<void> {
    const session: StoredSession = {
      userId: res.userId,
      email,
      deviceId: res.deviceId,
      refreshToken: res.refreshToken,
      kdf: res.kdf,
      wrappedVaultKey: res.wrappedVaultKey,
    };
    await this.store.setSession(session);
    this.session = session;
  }

  private async enterVault(): Promise<void> {
    const s = this.session;
    if (!s) throw new UserError("NO_SESSION");
    this.engine = new SyncEngine(this.api, this.store, this.crypto, s.userId);
    useApp.setState({ phase: "unlocked", screen: { name: "vault" }, notice: null, email: s.email });
    await this.refreshView();
    void this.syncNow();
    this.startTimers();
  }

  // ------------------------------------------------------------------ vault edits

  async saveToken(id: string | null, value: TokenItem): Promise<string> {
    const s = this.requireUnlocked();
    const itemId = id ?? uuidv7();
    const [enc] = await this.crypto.call("encrypt", {
      userId: s.userId,
      items: [{ id: itemId, kind: "token", value }],
    });
    if (!enc) throw new UserError("ENCRYPT_FAILED");
    await this.store.queueChange({ id: itemId, kind: "token", blob: enc.blob });
    await this.refreshView();
    this.scheduleSync();
    return itemId;
  }

  async trashToken(id: string): Promise<void> {
    const t = this.findToken(id);
    await this.saveToken(id, { ...t.value, trashedAt: Date.now() });
  }

  async restoreToken(id: string): Promise<void> {
    const t = this.findToken(id);
    await this.saveToken(id, { ...t.value, trashedAt: null });
  }

  /** Permanent delete: leaves a tombstone on the server. */
  async deleteToken(id: string): Promise<void> {
    this.requireUnlocked();
    await this.store.queueChange({ id, kind: "token", blob: null });
    await this.refreshView();
    this.scheduleSync();
  }

  /** HOTP: advance the counter and save, so the next code is shown. */
  async nextHotp(id: string): Promise<void> {
    const t = this.findToken(id);
    await this.saveToken(id, { ...t.value, counter: t.value.counter + 1 });
  }

  private findToken(id: string): VaultToken {
    const t = useApp.getState().tokens.find((x) => x.id === id);
    if (!t) throw new UserError("NOT_FOUND");
    return t;
  }

  private requireUnlocked(): StoredSession {
    if (!this.session || useApp.getState().phase !== "unlocked") throw new UserError("LOCKED");
    return this.session;
  }

  // ------------------------------------------------------------------ account

  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    const s = this.requireUnlocked();
    const keys = await this.crypto.call("changePassword", {
      userId: s.userId,
      currentPassword,
      currentKdf: s.kdf,
      wrappedVaultKey: s.wrappedVaultKey,
      newPassword,
    });
    const res = await this.api.changePassword(keys);
    await this.adoptSession(s.email, res);
  }

  async deleteAccount(password: string): Promise<void> {
    const s = this.requireUnlocked();
    const { authKey } = await this.crypto.call("deriveAuthKey", { password, kdf: s.kdf });
    await this.api.deleteAccount(authKey);
    await this.store.wipe();
    this.session = null;
    await this.lock("accountDeleted");
  }

  currentDeviceId(): string | null {
    return this.session?.deviceId ?? null;
  }

  // ------------------------------------------------------------------ sync and view

  async syncNow(): Promise<void> {
    const engine = this.engine;
    if (!engine) return;
    useApp.setState({ sync: "syncing" });
    try {
      void this.api.time().catch((e: unknown) => {
        if (!(e instanceof ApiError)) throw e;
      });
      const res = await engine.sync();
      if (this.engine !== engine) return;
      useApp.setState((st) => ({
        sync: "idle",
        lastSyncAt: Date.now(),
        conflictsResolved: st.conflictsResolved + res.conflicts,
        rollbackDetected: st.rollbackDetected || res.rollbacks > 0,
      }));
      await this.refreshView();
      await this.purgeOldTrash();
    } catch (e: unknown) {
      if (this.engine !== engine) return;
      if (e instanceof ApiError) {
        useApp.setState({ sync: e.code === "NETWORK" ? "offline" : "error" });
        return;
      }
      useApp.setState({ sync: "error" });
      throw e;
    }
  }

  private scheduleSync(): void {
    clearTimeout(this.changeTimer);
    this.changeTimer = setTimeout(() => {
      void this.syncNow();
    }, LOCAL_CHANGE_DEBOUNCE_MS);
  }

  private startTimers(): void {
    this.stopTimers();
    this.syncTimer = setInterval(() => {
      if (document.visibilityState === "visible") void this.syncNow();
    }, SYNC_INTERVAL_MS);
  }

  private stopTimers(): void {
    clearInterval(this.syncTimer);
    clearTimeout(this.changeTimer);
  }

  /** Rebuilds the decrypted view: cached server items overlaid with unsynced local changes. */
  async refreshView(): Promise<void> {
    const s = this.session;
    if (!s) return;
    const [items, pending] = await Promise.all([this.store.allItems(), this.store.allPending()]);
    const effective = new Map<string, string>();
    for (const i of items) if (i.kind === "token" && i.blob !== null) effective.set(i.id, i.blob);
    for (const p of pending) {
      if (p.kind !== "token") continue;
      if (p.blob === null) effective.delete(p.id);
      else effective.set(p.id, p.blob);
    }
    const toDecrypt = [...effective].filter(([id, blob]) => this.plainCache.get(id)?.blob !== blob);
    if (toDecrypt.length > 0) {
      const results = await this.crypto.call("decrypt", {
        userId: s.userId,
        items: toDecrypt.map(([id, blob]) => ({ id, kind: "token" as const, blob })),
      });
      for (const r of results) {
        const blob = effective.get(r.id) ?? "";
        this.plainCache.set(r.id, {
          blob,
          token: r.ok && r.kind === "token" ? { id: r.id, value: r.value } : null,
        });
      }
    }
    for (const id of [...this.plainCache.keys()])
      if (!effective.has(id)) this.plainCache.delete(id);
    if (useApp.getState().phase !== "unlocked") return;
    const tokens: VaultToken[] = [];
    let unreadable = 0;
    for (const entry of this.plainCache.values()) {
      if (entry.token) tokens.push(entry.token);
      else unreadable++;
    }
    tokens.sort(compareTokens);
    useApp.setState({ tokens, unreadable });
  }

  /** Tokens in the trash for more than 30 days are deleted for good (build spec §2). */
  private async purgeOldTrash(): Promise<void> {
    const cutoff = Date.now() - TRASH_RETENTION_MS;
    const old = useApp
      .getState()
      .tokens.filter((t) => t.value.trashedAt !== null && t.value.trashedAt < cutoff);
    for (const t of old) await this.store.queueChange({ id: t.id, kind: "token", blob: null });
    if (old.length > 0) {
      await this.refreshView();
      this.scheduleSync();
    }
  }

  // ------------------------------------------------------------------ app updates

  /** Registers the service-worker update hook (D-018): apply now if locked, else on the next lock. */
  setPendingUpdate(apply: () => void): void {
    if (useApp.getState().phase !== "unlocked") {
      apply();
      return;
    }
    this.applyUpdate = apply;
    useApp.setState({ updateReady: true });
  }
}
