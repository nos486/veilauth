import { z } from "zod";
import { API_ERROR_CODES } from "./errors.js";

/** Limits shared by the Worker and the clients (spec/crypto.md, build spec §5.3). */
export const LIMITS = {
  maxItemsPerUser: 1000,
  maxBlobChars: 8192,
  maxChangesPerPush: 200,
  maxDeviceNameChars: 512,
  accessTokenTtlMs: 15 * 60 * 1000,
  refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
  tombstoneRetentionMs: 90 * 24 * 60 * 60 * 1000,
  auditRetentionMs: 180 * 24 * 60 * 60 * 1000,
} as const;

const B64U = /^[A-Za-z0-9_-]*$/;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const Base64Url = z.string().regex(B64U, "base64url without padding");
export const Id = z.string().regex(UUID_V7, "lowercase UUIDv7");
/** 32 bytes, base64url → 43 chars */
export const Key32 = Base64Url.length(43);
/** 16 bytes, base64url → 22 chars */
export const Salt16 = Base64Url.length(22);
/** Envelope of a 32-byte key: 61 bytes → 82 chars */
export const WrappedKey = Base64Url.length(82);
/** Item envelope: at least 1 + 12 + 256 + 16 bytes */
export const ItemBlob = Base64Url.min(380).max(LIMITS.maxBlobChars);
export const DeviceNameEnc = Base64Url.min(39).max(LIMITS.maxDeviceNameChars);
export const Email = z
  .string()
  .trim()
  .min(3)
  .max(254)
  .regex(/^[^\s@]+@[^\s@]+$/, "e-mail address");
export const Platform = z.enum(["web", "android"]);
export const ItemKind = z.enum(["token", "folder", "settings"]);
export const UnixMs = z.number().int().nonnegative();
export const Revision = z.number().int().nonnegative();

export const KdfParams = z.object({
  m: z.number().int(),
  t: z.number().int(),
  p: z.number().int(),
});

export const Kdf = z.object({
  alg: z.literal("argon2id"),
  version: z.number().int().positive(),
  params: KdfParams,
  salt: Salt16,
});

export const DeviceInfo = z.object({
  id: Id,
  platform: Platform,
  nameEnc: DeviceNameEnc.nullable(),
});

export const TurnstileToken = z.string().min(1).max(2048);

// ---------------------------------------------------------------- auth

export const PreloginRequest = z.object({ email: Email });
export const PreloginResponse = z.object({ kdf: Kdf });

export const RecoveryData = z.object({
  authKey: Key32,
  wrappedVaultKey: WrappedKey,
});

export const RegisterRequest = z.object({
  userId: Id,
  email: Email,
  kdf: Kdf,
  authKey: Key32,
  wrappedVaultKey: WrappedKey,
  recovery: RecoveryData,
  device: DeviceInfo,
  turnstileToken: TurnstileToken.optional(),
});

export const LoginRequest = z.object({
  email: Email,
  authKey: Key32,
  device: DeviceInfo,
  turnstileToken: TurnstileToken.optional(),
});

export const SessionResponse = z.object({
  userId: Id,
  deviceId: Id,
  accessToken: z.string(),
  accessTokenExpiresAt: UnixMs,
  refreshToken: Key32,
  wrappedVaultKey: WrappedKey,
  kdf: Kdf,
  vaultRevision: Revision,
  /** true when the stored KDF params are older than the current default: re-wrap via change-password */
  kdfUpgradeRequired: z.boolean(),
});

export const RefreshRequest = z.object({ refreshToken: Key32 });
export const RefreshResponse = z.object({
  accessToken: z.string(),
  accessTokenExpiresAt: UnixMs,
  refreshToken: Key32,
});

export const ChangePasswordRequest = z.object({
  authKey: Key32,
  newKdf: Kdf,
  newAuthKey: Key32,
  newWrappedVaultKey: WrappedKey,
});

export const RecoverStartRequest = z.object({
  email: Email,
  recoveryAuthKey: Key32,
});
export const RecoverStartResponse = z.object({
  userId: Id,
  recoveryWrappedVaultKey: WrappedKey,
});

export const RecoverRequest = z.object({
  email: Email,
  recoveryAuthKey: Key32,
  newKdf: Kdf,
  newAuthKey: Key32,
  newWrappedVaultKey: WrappedKey,
  newRecovery: RecoveryData,
  device: DeviceInfo,
});

export const DeleteAccountRequest = z.object({ authKey: Key32 });

// ---------------------------------------------------------------- sync

export const VaultItem = z.object({
  id: Id,
  kind: ItemKind,
  /** null for tombstones */
  blob: ItemBlob.nullable(),
  revision: Revision,
  deleted: z.boolean(),
  updatedAt: UnixMs,
});

export const SyncQuery = z.object({
  since: z.coerce.number().int().nonnegative().default(0),
});

export const SyncResponse = z.object({
  /** current users.vault_revision */
  revision: Revision,
  /** true when `since` was older than the tombstone purge horizon: replace the local cache with `items` */
  full: z.boolean(),
  items: z.array(VaultItem),
});

export const PushChange = z.object({
  id: Id,
  kind: ItemKind,
  /** null deletes (tombstone) */
  blob: ItemBlob.nullable(),
  /** revision the client last saw for this item; 0 for a new item */
  baseRevision: Revision,
});

export const PushRequest = z.object({
  changes: z.array(PushChange).min(1).max(LIMITS.maxChangesPerPush),
});

export const PushConflict = z.object({
  id: Id,
  reason: z.enum(["revision_mismatch", "kind_mismatch"]),
  /** server copy, null if the item does not exist (e.g. purged) */
  server: VaultItem.nullable(),
});

export const PushResponse = z.object({
  revision: Revision,
  applied: z.array(z.object({ id: Id, revision: Revision })),
  conflicts: z.array(PushConflict),
});

// ---------------------------------------------------------------- misc

export const Device = z.object({
  id: Id,
  platform: Platform,
  nameEnc: DeviceNameEnc.nullable(),
  createdAt: UnixMs,
  lastSeenAt: UnixMs,
  current: z.boolean(),
});
export const DevicesResponse = z.object({ devices: z.array(Device) });

export const TimeResponse = z.object({ now: UnixMs });

export const ConfigResponse = z.object({
  turnstileSiteKey: z.string().nullable(),
  kdf: z.object({ alg: z.literal("argon2id"), version: z.number().int(), params: KdfParams }),
  limits: z.object({
    maxItemsPerUser: z.number().int(),
    maxBlobChars: z.number().int(),
    maxChangesPerPush: z.number().int(),
  }),
});

export const ApiError = z.object({
  code: z.enum(API_ERROR_CODES),
  message: z.string(),
});

export type PreloginRequest = z.infer<typeof PreloginRequest>;
export type PreloginResponse = z.infer<typeof PreloginResponse>;
export type RegisterRequest = z.infer<typeof RegisterRequest>;
export type LoginRequest = z.infer<typeof LoginRequest>;
export type SessionResponse = z.infer<typeof SessionResponse>;
export type RefreshRequest = z.infer<typeof RefreshRequest>;
export type RefreshResponse = z.infer<typeof RefreshResponse>;
export type ChangePasswordRequest = z.infer<typeof ChangePasswordRequest>;
export type RecoverStartRequest = z.infer<typeof RecoverStartRequest>;
export type RecoverStartResponse = z.infer<typeof RecoverStartResponse>;
export type RecoverRequest = z.infer<typeof RecoverRequest>;
export type DeleteAccountRequest = z.infer<typeof DeleteAccountRequest>;
export type VaultItem = z.infer<typeof VaultItem>;
export type SyncResponse = z.infer<typeof SyncResponse>;
export type PushChange = z.infer<typeof PushChange>;
export type PushRequest = z.infer<typeof PushRequest>;
export type PushConflict = z.infer<typeof PushConflict>;
export type PushResponse = z.infer<typeof PushResponse>;
export type Device = z.infer<typeof Device>;
export type DevicesResponse = z.infer<typeof DevicesResponse>;
export type TimeResponse = z.infer<typeof TimeResponse>;
export type ConfigResponse = z.infer<typeof ConfigResponse>;
export type ApiError = z.infer<typeof ApiError>;
export type Kdf = z.infer<typeof Kdf>;
export type DeviceInfo = z.infer<typeof DeviceInfo>;
