import { describe, expect, it } from "vitest";
import { newTokenItem } from "../src/lib/tokens";
import { uuidv7 } from "../src/lib/uuid";
import { DirectCryptoClient, STRONG_PASSWORD } from "./helpers";

const token = newTokenItem(
  {
    type: "totp",
    issuer: "Example",
    account: "alice@example.com",
    secret: "JBSWY3DPEHPK3PXP", // gitleaks:allow (public test value)
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    counter: 0,
  },
  1_700_000_000_000,
);

describe("crypto worker handler", () => {
  it("registers, then logs in on a second device and decrypts the first device's items", async () => {
    const userId = uuidv7();
    const deviceA = new DirectCryptoClient();
    const reg = await deviceA.call("register", { password: STRONG_PASSWORD, userId });
    expect(reg.mnemonic.split(" ")).toHaveLength(24);
    expect(reg.kdf.params).toEqual({ m: 65536, t: 3, p: 1 });

    const itemId = uuidv7();
    const [enc] = await deviceA.call("encrypt", {
      userId,
      items: [{ id: itemId, kind: "token", value: token }],
    });
    expect(enc?.blob).toMatch(/^[A-Za-z0-9_-]+$/);

    const deviceB = new DirectCryptoClient();
    const { authKey } = await deviceB.call("deriveLogin", {
      password: STRONG_PASSWORD,
      kdf: reg.kdf,
    });
    expect(authKey).toBe(reg.authKey);
    await deviceB.call("unlock", { userId, wrappedVaultKey: reg.wrappedVaultKey });
    const [dec] = await deviceB.call("decrypt", {
      userId,
      items: [{ id: itemId, kind: "token", blob: enc?.blob ?? "" }],
    });
    expect(dec).toMatchObject({ id: itemId, ok: true, kind: "token", value: token });
  });

  it("reports a wrong password without unlocking, and tampered items without failing the batch", async () => {
    const userId = uuidv7();
    const a = new DirectCryptoClient();
    const reg = await a.call("register", { password: STRONG_PASSWORD, userId });
    const id = uuidv7();
    const [enc] = await a.call("encrypt", { userId, items: [{ id, kind: "token", value: token }] });

    const b = new DirectCryptoClient();
    const wrong = await b.call("unlockWithPassword", {
      password: "not the password at all",
      kdf: reg.kdf,
      userId,
      wrappedVaultKey: reg.wrappedVaultKey,
    });
    expect(wrong.unlocked).toBe(false);
    await expect(
      b.call("encrypt", { userId, items: [{ id, kind: "token", value: token }] }),
    ).rejects.toMatchObject({
      code: "INVALID_CONTEXT",
    });

    const blob = enc?.blob ?? "";
    const flipped = blob.slice(0, 40) + (blob[40] === "A" ? "B" : "A") + blob.slice(41);
    const results = await a.call("decrypt", {
      userId,
      items: [
        { id, kind: "token", blob },
        { id, kind: "token", blob: flipped },
        { id: uuidv7(), kind: "token", blob }, // moved to another id: AAD mismatch
        { id, kind: "folder", blob }, // wrong kind
      ],
    });
    expect(results.map((r) => r.ok)).toEqual([true, false, false, false]);
  });

  it("changes the password without changing the vault key", async () => {
    const userId = uuidv7();
    const a = new DirectCryptoClient();
    const reg = await a.call("register", { password: STRONG_PASSWORD, userId });
    const id = uuidv7();
    const [enc] = await a.call("encrypt", { userId, items: [{ id, kind: "token", value: token }] });
    const newPassword = "Granite meadow cobalt whisper 7?";
    const change = await a.call("changePassword", {
      userId,
      currentPassword: STRONG_PASSWORD,
      currentKdf: reg.kdf,
      wrappedVaultKey: reg.wrappedVaultKey,
      newPassword,
    });
    expect(change.authKey).toBe(reg.authKey);
    expect(change.newKdf.salt).not.toBe(reg.kdf.salt);

    const b = new DirectCryptoClient();
    const res = await b.call("unlockWithPassword", {
      password: newPassword,
      kdf: change.newKdf,
      userId,
      wrappedVaultKey: change.newWrappedVaultKey,
    });
    expect(res).toEqual({ authKey: change.newAuthKey, unlocked: true });
    const [dec] = await b.call("decrypt", {
      userId,
      items: [{ id, kind: "token", blob: enc?.blob ?? "" }],
    });
    expect(dec?.ok).toBe(true);
  });

  it("forgets the vault key on lock", async () => {
    const userId = uuidv7();
    const a = new DirectCryptoClient();
    await a.call("register", { password: STRONG_PASSWORD, userId });
    expect(a.handler.unlocked).toBe(true);
    await a.call("lock", {});
    expect(a.handler.unlocked).toBe(false);
  });

  it("refuses weakened KDF parameters from the server", async () => {
    const a = new DirectCryptoClient();
    await expect(
      a.call("deriveLogin", {
        password: STRONG_PASSWORD,
        kdf: {
          alg: "argon2id",
          version: 1,
          params: { m: 1024, t: 1, p: 1 },
          salt: "AAAAAAAAAAAAAAAAAAAAAA",
        },
      }),
    ).rejects.toMatchObject({ code: "KDF_PARAMS_REJECTED" });
  });
});
