import {
  createAccountKeys,
  createBackup,
  openBackup,
  CryptoError,
  decryptItem,
  DEFAULT_KDF_PARAMS,
  deriveLoginKeys,
  encryptItem,
  fromBase64Url,
  KDF_ALG,
  CURRENT_KDF_VERSION,
  KDF_SALT_BYTES,
  randomBytes,
  toBase64Url,
  unwrapVaultKey,
  validateFolderItem,
  validateTokenItem,
  wipe,
  wrapVaultKey,
} from "@zk2fa/crypto";
import type { CryptoOp, CryptoOps, DecryptResult, PlainValue, WireKdf } from "./protocol";

/**
 * Crypto operations behind the worker boundary (docs/DECISIONS.md D-017). The vault key is a
 * non-extractable CryptoKey that only this module holds; the main thread gets ciphertext,
 * decrypted items and the authKey it must send to the server, never key material.
 */
export class CryptoHandler {
  private vaultKey: CryptoKey | null = null;
  private pendingKek: CryptoKey | null = null;

  get unlocked(): boolean {
    return this.vaultKey !== null;
  }

  private readonly ops: {
    [K in CryptoOp]: (req: CryptoOps[K]["req"]) => Promise<CryptoOps[K]["res"]>;
  } = {
    register: (r) => this.register(r),
    deriveLogin: (r) => this.deriveLogin(r),
    unlock: (r) => this.unlock(r),
    unlockWithPassword: (r) => this.unlockWithPassword(r),
    deriveAuthKey: (r) => this.deriveAuthKey(r),
    decrypt: (r) => this.decrypt(r),
    encrypt: (r) => this.encrypt(r),
    changePassword: (r) => this.changePassword(r),
    createBackup: async (r) => ({ file: await createBackup(r.password, r.contents) }),
    openBackup: (r) => openBackup(r.password, r.file),
    lock: () => {
      this.lock();
      return Promise.resolve({ locked: true });
    },
  };

  handle<K extends CryptoOp>(op: K, req: CryptoOps[K]["req"]): Promise<CryptoOps[K]["res"]> {
    // Messages come from our own page, but check the op name anyway before dispatching.
    if (!Object.prototype.hasOwnProperty.call(this.ops, op)) {
      return Promise.reject(new CryptoError("INVALID_CONTEXT", "unknown operation"));
    }
    const fn = this.ops[op] as (r: CryptoOps[K]["req"]) => Promise<CryptoOps[K]["res"]>;
    return fn(req);
  }

  lock(): void {
    this.vaultKey = null;
    this.pendingKek = null;
  }

  private requireVaultKey(): CryptoKey {
    if (!this.vaultKey) throw new CryptoError("INVALID_CONTEXT", "vault is locked");
    return this.vaultKey;
  }

  private async register(req: CryptoOps["register"]["req"]): Promise<CryptoOps["register"]["res"]> {
    const keys = await createAccountKeys(req.password, req.userId);
    try {
      this.vaultKey = keys.vaultKey;
      return {
        kdf: {
          alg: keys.kdf.alg,
          version: keys.kdf.version,
          params: { ...keys.kdf.params },
          salt: toBase64Url(keys.kdf.salt),
        },
        authKey: toBase64Url(keys.authKey),
        wrappedVaultKey: keys.wrappedVaultKey,
        recovery: {
          authKey: toBase64Url(keys.recoveryAuth),
          wrappedVaultKey: keys.recoveryWrappedVaultKey,
        },
        mnemonic: keys.recoveryMnemonic,
      };
    } finally {
      wipe(keys.authKey, keys.recoveryAuth);
    }
  }

  private async derive(password: string, kdf: WireKdf) {
    return deriveLoginKeys(password, fromBase64Url(kdf.salt), kdf.params, kdf.alg);
  }

  private async deriveLogin(
    req: CryptoOps["deriveLogin"]["req"],
  ): Promise<CryptoOps["deriveLogin"]["res"]> {
    const { authKey, kek } = await this.derive(req.password, req.kdf);
    this.pendingKek = kek;
    try {
      return { authKey: toBase64Url(authKey) };
    } finally {
      wipe(authKey);
    }
  }

  private async unlock(req: CryptoOps["unlock"]["req"]): Promise<CryptoOps["unlock"]["res"]> {
    const kek = this.pendingKek;
    if (!kek) throw new CryptoError("INVALID_CONTEXT", "no key derived");
    this.pendingKek = null;
    this.vaultKey = await unwrapVaultKey(kek, req.wrappedVaultKey, req.userId);
    return { unlocked: true };
  }

  private async unlockWithPassword(
    req: CryptoOps["unlockWithPassword"]["req"],
  ): Promise<CryptoOps["unlockWithPassword"]["res"]> {
    const { authKey, kek } = await this.derive(req.password, req.kdf);
    try {
      try {
        this.vaultKey = await unwrapVaultKey(kek, req.wrappedVaultKey, req.userId);
        this.pendingKek = null;
        return { authKey: toBase64Url(authKey), unlocked: true };
      } catch (e: unknown) {
        if (!(e instanceof CryptoError) || e.code !== "DECRYPT_FAILED") throw e;
        // Wrong password, or the cached wrap is stale. Keep the KEK for an online `unlock`.
        this.pendingKek = kek;
        return { authKey: toBase64Url(authKey), unlocked: false };
      }
    } finally {
      wipe(authKey);
    }
  }

  private async deriveAuthKey(
    req: CryptoOps["deriveAuthKey"]["req"],
  ): Promise<CryptoOps["deriveAuthKey"]["res"]> {
    const { authKey } = await this.derive(req.password, req.kdf);
    try {
      return { authKey: toBase64Url(authKey) };
    } finally {
      wipe(authKey);
    }
  }

  private async decrypt(req: CryptoOps["decrypt"]["req"]): Promise<DecryptResult[]> {
    const key = this.requireVaultKey();
    return Promise.all(
      req.items.map(async (item): Promise<DecryptResult> => {
        try {
          const raw = await decryptItem(
            key,
            { userId: req.userId, itemId: item.id, kind: item.kind },
            item.blob,
          );
          return { id: item.id, ok: true, ...toPlain(item.kind, raw) };
        } catch (e: unknown) {
          // One bad item must not hide the rest of the vault; the caller reports it.
          if (e instanceof CryptoError) return { id: item.id, ok: false, code: e.code };
          throw e;
        }
      }),
    );
  }

  private async encrypt(req: CryptoOps["encrypt"]["req"]): Promise<CryptoOps["encrypt"]["res"]> {
    const key = this.requireVaultKey();
    return Promise.all(
      req.items.map(async (item) => {
        const checked = toPlain(item.kind, item.value);
        return {
          id: item.id,
          blob: await encryptItem(
            key,
            { userId: req.userId, itemId: item.id, kind: item.kind },
            checked.value,
          ),
        };
      }),
    );
  }

  private async changePassword(
    req: CryptoOps["changePassword"]["req"],
  ): Promise<CryptoOps["changePassword"]["res"]> {
    const current = await this.derive(req.currentPassword, req.currentKdf);
    // Extractable only for the moment it takes to re-wrap; the session key stays non-extractable.
    const vaultKey = await unwrapVaultKey(current.kek, req.wrappedVaultKey, req.userId, {
      extractable: true,
    });
    const salt = randomBytes(KDF_SALT_BYTES);
    const params = { ...DEFAULT_KDF_PARAMS };
    const next = await deriveLoginKeys(req.newPassword, salt, params);
    try {
      const newWrappedVaultKey = await wrapVaultKey(next.kek, vaultKey, req.userId);
      return {
        authKey: toBase64Url(current.authKey),
        newKdf: { alg: KDF_ALG, version: CURRENT_KDF_VERSION, params, salt: toBase64Url(salt) },
        newAuthKey: toBase64Url(next.authKey),
        newWrappedVaultKey,
      };
    } finally {
      wipe(current.authKey, next.authKey);
    }
  }
}

function toPlain(kind: string, raw: unknown): PlainValue {
  switch (kind) {
    case "token":
      return { kind, value: validateTokenItem(raw) };
    case "folder":
      return { kind, value: validateFolderItem(raw) };
    case "settings":
      if (typeof raw !== "object" || raw === null || Array.isArray(raw))
        throw new CryptoError("INVALID_ITEM");
      return { kind, value: raw as Record<string, unknown> };
    default:
      throw new CryptoError("INVALID_CONTEXT", "unknown item kind");
  }
}
