import type { BackupContents, FolderItem, ItemKind, TokenItem } from "@zk2fa/crypto";

/** KDF description as it travels over the API (salt is base64url). */
export interface WireKdf {
  alg: "argon2id";
  version: number;
  params: { m: number; t: number; p: number };
  salt: string;
}

export interface CipherItem {
  id: string;
  kind: ItemKind;
  blob: string;
}

export type PlainValue =
  | { kind: "token"; value: TokenItem }
  | { kind: "folder"; value: FolderItem }
  | { kind: "settings"; value: Record<string, unknown> };

export type DecryptResult =
  ({ id: string; ok: true } & PlainValue) | { id: string; ok: false; code: string };

export interface RegistrationKeys {
  kdf: WireKdf;
  authKey: string;
  wrappedVaultKey: string;
  recovery: { authKey: string; wrappedVaultKey: string };
  /** 24 words, shown once */
  mnemonic: string;
}

export interface PasswordChangeKeys {
  authKey: string;
  newKdf: WireKdf;
  newAuthKey: string;
  newWrappedVaultKey: string;
}

/** Every operation the crypto worker understands: request and result types. */
export interface CryptoOps {
  /** Creates all signup keys; the new vault key stays in the worker. */
  register: { req: { password: string; userId: string }; res: RegistrationKeys };
  /** Derives authKey for login; the KEK stays in the worker for `unlock`. */
  deriveLogin: { req: { password: string; kdf: WireKdf }; res: { authKey: string } };
  /** Unwraps the vault key with the KEK from the last `deriveLogin`, then forgets the KEK. */
  unlock: { req: { userId: string; wrappedVaultKey: string }; res: { unlocked: true } };
  /**
   * Offline unlock from the cached wrapped key. Returns authKey too so the caller can log in
   * online when the cached wrap is stale (password changed elsewhere).
   */
  unlockWithPassword: {
    req: { password: string; kdf: WireKdf; userId: string; wrappedVaultKey: string };
    res: { authKey: string; unlocked: boolean };
  };
  /** authKey only, nothing kept (re-authentication for sensitive actions). */
  deriveAuthKey: { req: { password: string; kdf: WireKdf }; res: { authKey: string } };
  decrypt: { req: { userId: string; items: CipherItem[] }; res: DecryptResult[] };
  encrypt: {
    req: { userId: string; items: ({ id: string } & PlainValue)[] };
    res: { id: string; blob: string }[];
  };
  changePassword: {
    req: {
      userId: string;
      currentPassword: string;
      currentKdf: WireKdf;
      wrappedVaultKey: string;
      newPassword: string;
    };
    res: PasswordChangeKeys;
  };
  /** Encrypts tokens into a backup file under a backup password; needs no vault key. */
  createBackup: { req: { password: string; contents: BackupContents }; res: { file: string } };
  /** Opens a backup file; the tokens are validated but not yet added to the vault. */
  openBackup: { req: { password: string; file: string }; res: BackupContents };
  lock: { req: Record<string, never>; res: { locked: true } };
}

export type CryptoOp = keyof CryptoOps;

export interface CryptoRequestMessage<K extends CryptoOp = CryptoOp> {
  id: number;
  op: K;
  req: CryptoOps[K]["req"];
}

export type CryptoResponseMessage =
  { id: number; ok: true; res: unknown } | { id: number; ok: false; code: string };
