import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  createAccountKeys,
  ctx,
  decryptItem,
  deriveLoginKeys,
  deriveRecoveryKeys,
  encryptItem,
  fromBase64Url,
  importAesKey,
  mnemonicToRecoveryKey,
  open,
  seal,
  unwrapVaultKey,
  unwrapVaultKeyWithRecovery,
  utf8,
  validateTokenItem,
  wrapVaultKey,
  wrapVaultKeyForRecovery,
} from "../src/index.js";

const USER = "0192d5f0-6a3c-7c1e-8b2a-3f4e5d6c7b8a";
const ITEM = "0192d5f1-0000-7000-8000-000000000001";

const token = {
  type: "totp",
  issuer: "GitHub",
  account: "alice",
  secret: "JBSWY3DPEHPK3PXP",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  counter: 0,
  iconId: null,
  folderId: null,
  tags: [],
  notes: "",
  favorite: false,
  createdAt: 1760000000000,
  trashedAt: null,
};

describe("envelope", () => {
  it("uses a fresh nonce every time", async () => {
    const key = await importAesKey(new Uint8Array(32).fill(7));
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const env = fromBase64Url(await seal(key, utf8("same"), "c"));
      seen.add(Buffer.from(env.slice(1, 13)).toString("hex"));
    }
    expect(seen.size).toBe(200);
  });

  it("round-trips and binds the context", async () => {
    const key = await importAesKey(new Uint8Array(32).fill(1));
    const env = await seal(key, utf8("hello"), "ctx-a");
    expect(new TextDecoder().decode(await open(key, env, "ctx-a"))).toBe("hello");
    await expect(open(key, env, "ctx-b")).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
  });
});

describe("AAD contexts", () => {
  it.each([
    ["uppercase id", () => ctx.item(USER.toUpperCase(), ITEM, "token")],
    ["separator injection", () => ctx.item(`${USER}|x`, ITEM, "token")],
    ["uuid v4", () => ctx.vaultKey("0192d5f0-6a3c-4c1e-8b2a-3f4e5d6c7b8a")],
    ["unknown kind", () => ctx.item(USER, ITEM, "password")],
  ])("rejects %s", (_name, fn) => {
    expect(fn).toThrow(expect.objectContaining({ code: "INVALID_CONTEXT" }) as Error);
  });
});

describe("canonical JSON", () => {
  it.each([[1.5], [Number.NaN], [2 ** 53], [{ a: undefined }], [new Date(0)], ["\ud800"]])(
    "rejects %s",
    (v) => {
      expect(() => canonicalJson(v)).toThrow(
        expect.objectContaining({ code: "INVALID_ITEM" }) as Error,
      );
    },
  );

  it("sorts keys by code unit and escapes like RFC 8785", () => {
    expect(canonicalJson({ b: [true, null, -0], a: "é\u0007\n", A: 1 })).toBe(
      '{"A":1,"a":"é\\u0007\\n","b":[true,null,0]}',
    );
  });
});

describe("items", () => {
  it("preserves unknown fields (forward compatibility)", async () => {
    const key = await importAesKey(new Uint8Array(32).fill(3));
    const ref = { userId: USER, itemId: ITEM, kind: "token" as const };
    const future = { ...token, futureField: { x: 1 } };
    const out = validateTokenItem(await decryptItem(key, ref, await encryptItem(key, ref, future)));
    expect(out).toEqual(future);
  });

  it("hides length inside 256-byte buckets", async () => {
    const key = await importAesKey(new Uint8Array(32).fill(3));
    const ref = { userId: USER, itemId: ITEM, kind: "token" as const };
    const sizes = new Set<number>();
    for (let n = 0; n < 200; n += 7) {
      const env = fromBase64Url(await encryptItem(key, ref, { ...token, notes: "x".repeat(n) }));
      expect((env.length - 29) % 256).toBe(0);
      sizes.add(env.length);
    }
    expect(sizes.size).toBeLessThanOrEqual(2);
  });

  it("refuses items over the blob limit", async () => {
    const key = await importAesKey(new Uint8Array(32).fill(3));
    const ref = { userId: USER, itemId: ITEM, kind: "token" as const };
    await expect(
      encryptItem(key, ref, { ...token, notes: "x".repeat(6000) }),
    ).rejects.toMatchObject({
      code: "ITEM_TOO_LARGE",
    });
  });

  it.each([
    ["bad type", { type: "sms" }],
    ["bad digits", { digits: 9 }],
    ["steam digits", { type: "steam", digits: 6 }],
    ["lowercase secret", { secret: "jbswy3dpehpk3pxp" }],
    ["float period", { period: 30.5 }],
    ["missing favorite", { favorite: undefined }],
  ])("validateTokenItem rejects %s", (_n, patch) => {
    expect(() => validateTokenItem({ ...token, ...patch })).toThrow(
      expect.objectContaining({ code: "INVALID_ITEM" }) as Error,
    );
  });
});

describe("account flows", () => {
  it("signup → login → item → password change → recovery", async () => {
    const acct = await createAccountKeys("old password ✓", USER);
    expect(acct.recoveryMnemonic.split(" ")).toHaveLength(24);
    expect(acct.vaultKey.extractable).toBe(false);
    const ref = { userId: USER, itemId: ITEM, kind: "token" as const };
    const blob = await encryptItem(acct.vaultKey, ref, token);

    // Login on another device.
    const login = await deriveLoginKeys("old password ✓", acct.kdf.salt, acct.kdf.params);
    expect(login.authKey).toEqual(acct.authKey);
    const vk = await unwrapVaultKey(login.kek, acct.wrappedVaultKey, USER);
    expect(await decryptItem(vk, ref, blob)).toEqual(token);

    // Password change: same vault key, new wrap, item untouched.
    const forRewrap = await unwrapVaultKey(login.kek, acct.wrappedVaultKey, USER, {
      extractable: true,
    });
    const salt2 = new Uint8Array(16).fill(9);
    const next = await deriveLoginKeys("new password", salt2, acct.kdf.params);
    const rewrapped = await wrapVaultKey(next.kek, forRewrap, USER);
    expect(next.authKey).not.toEqual(acct.authKey);
    const vk2 = await unwrapVaultKey(next.kek, rewrapped, USER);
    expect(await decryptItem(vk2, ref, blob)).toEqual(token);
    await expect(unwrapVaultKey(login.kek, rewrapped, USER)).rejects.toMatchObject({
      code: "DECRYPT_FAILED",
    });

    // Recovery with the 24 words.
    const { recoveryKek } = await deriveRecoveryKeys(mnemonicToRecoveryKey(acct.recoveryMnemonic));
    const vk3 = await unwrapVaultKeyWithRecovery(recoveryKek, acct.recoveryWrappedVaultKey, USER, {
      extractable: true,
    });
    expect(await decryptItem(vk3, ref, blob)).toEqual(token);
    const fresh = await deriveRecoveryKeys(new Uint8Array(32).fill(4));
    const newRecoveryWrap = await wrapVaultKeyForRecovery(fresh.recoveryKek, vk3, USER);
    const vk4 = await unwrapVaultKeyWithRecovery(fresh.recoveryKek, newRecoveryWrap, USER);
    expect(await decryptItem(vk4, ref, blob)).toEqual(token);
  });

  it("refuses to re-wrap a non-extractable vault key", async () => {
    const acct = await createAccountKeys("pw", USER);
    await expect(wrapVaultKey(acct.vaultKey, acct.vaultKey, USER)).rejects.toMatchObject({
      code: "INVALID_CONTEXT",
    });
  });
});
