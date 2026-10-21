import {
  customType,
  index,
  integer,
  sqliteTable,
  text,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

/** BLOB ↔ Uint8Array without Node's Buffer. D1 returns blobs as number[] or ArrayBuffer. */
const bytes = customType<{ data: Uint8Array; driverData: ArrayBuffer | number[] | Uint8Array }>({
  dataType: () => "blob",
  toDriver: (value) => value.slice().buffer,
  fromDriver: (value) => (value instanceof Uint8Array ? value : new Uint8Array(value)),
});

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  kdfAlg: text("kdf_alg").notNull(),
  kdfParams: text("kdf_params").notNull(),
  kdfSalt: bytes("kdf_salt").notNull(),
  kdfVersion: integer("kdf_version").notNull(),
  authHash: bytes("auth_hash").notNull(),
  authSalt: bytes("auth_salt").notNull(),
  wrappedVaultKey: text("wrapped_vault_key").notNull(),
  recoveryWrappedVaultKey: text("recovery_wrapped_vault_key").notNull(),
  recoveryAuthHash: bytes("recovery_auth_hash").notNull(),
  recoveryAuthSalt: bytes("recovery_auth_salt").notNull(),
  vaultRevision: integer("vault_revision").notNull().default(0),
  tombstoneHorizon: integer("tombstone_horizon").notNull().default(0),
  securityStamp: text("security_stamp").notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
});

export const devices = sqliteTable(
  "devices",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    nameEnc: text("name_enc"),
    platform: text("platform", { enum: ["web", "android"] }).notNull(),
    refreshHash: bytes("refresh_hash").notNull(),
    refreshFamily: text("refresh_family").notNull(),
    refreshExpiresAt: integer("refresh_expires_at").notNull(),
    lastSeenAt: integer("last_seen_at").notNull(),
    createdAt: integer("created_at").notNull(),
    revokedAt: integer("revoked_at"),
  },
  (t) => [
    index("idx_devices_user").on(t.userId),
    uniqueIndex("idx_devices_refresh").on(t.refreshHash),
  ],
);

export const refreshHistory = sqliteTable(
  "refresh_history",
  {
    tokenHash: bytes("token_hash").primaryKey(),
    family: text("family").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    expiresAt: integer("expires_at").notNull(),
  },
  (t) => [index("idx_refresh_history_expiry").on(t.expiresAt)],
);

export const vaultItems = sqliteTable(
  "vault_items",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    kind: text("kind", { enum: ["token", "folder", "settings"] }).notNull(),
    blob: text("blob"),
    revision: integer("revision").notNull(),
    deleted: integer("deleted", { mode: "boolean" }).notNull().default(false),
    updatedAt: integer("updated_at").notNull(),
  },
  (t) => [index("idx_items_user_rev").on(t.userId, t.revision)],
);

export const auditLog = sqliteTable(
  "audit_log",
  {
    id: text("id").primaryKey(),
    userId: text("user_id").notNull(),
    deviceId: text("device_id"),
    event: text("event").notNull(),
    ipHash: text("ip_hash"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [
    index("idx_audit_user").on(t.userId, t.createdAt),
    index("idx_audit_created").on(t.createdAt),
  ],
);

export const counters = sqliteTable(
  "counters",
  {
    key: text("key").primaryKey(),
    count: integer("count").notNull(),
    windowStart: integer("window_start").notNull(),
    lockedUntil: integer("locked_until").notNull().default(0),
    expiresAt: integer("expires_at").notNull(),
  },
  (t) => [index("idx_counters_expiry").on(t.expiresAt)],
);

export type UserRow = typeof users.$inferSelect;
export type DeviceRow = typeof devices.$inferSelect;
export type VaultItemRow = typeof vaultItems.$inferSelect;
