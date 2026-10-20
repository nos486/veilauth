import { CryptoError } from "./errors.js";

const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const ITEM_KINDS = ["token", "folder", "settings"] as const;
export type ItemKind = (typeof ITEM_KINDS)[number];

export function assertId(id: string): void {
  if (!UUID_V7.test(id)) throw new CryptoError("INVALID_CONTEXT", "id must be a lowercase UUIDv7");
}

export function isItemKind(kind: string): kind is ItemKind {
  return (ITEM_KINDS as readonly string[]).includes(kind);
}

/** AAD contexts (spec/crypto.md §5). Every component is validated so "|" cannot be injected. */
export const ctx = {
  vaultKey(userId: string): string {
    assertId(userId);
    return `zk2fa/v1/vk|${userId}`;
  },
  recoveryVaultKey(userId: string): string {
    assertId(userId);
    return `zk2fa/v1/rvk|${userId}`;
  },
  item(userId: string, itemId: string, kind: string): string {
    assertId(userId);
    assertId(itemId);
    if (!isItemKind(kind)) throw new CryptoError("INVALID_CONTEXT", "unknown item kind");
    return `zk2fa/v1/item|${userId}|${itemId}|${kind}`;
  },
  device(userId: string, deviceId: string): string {
    assertId(userId);
    assertId(deviceId);
    return `zk2fa/v1/device|${userId}|${deviceId}`;
  },
} as const;
