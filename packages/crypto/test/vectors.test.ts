import { describe, expect, it } from "vitest";
import {
  argon2idRaw,
  canonicalJson,
  ctx,
  decryptItem,
  deriveLoginKeys,
  deriveMasterKey,
  deriveRecoveryKeys,
  fromBase64Url,
  hkdfSha256,
  importAesKey,
  INFO_AUTH,
  INFO_KEK,
  INFO_RECOVERY_AUTH,
  INFO_RECOVERY_KEK,
  mnemonicToRecoveryKey,
  normalizePassword,
  open,
  openBackup,
  padPlaintext,
  recoveryKeyToMnemonic,
  toBase64Url,
  unpadPlaintext,
  unwrapVaultKey,
  unwrapVaultKeyWithRecovery,
  utf8,
  validateFolderItem,
  validateKdfParams,
  validateTokenItem,
} from "../src/index.js";
import { computeAuthHash, fakeSalt, verifyAuthHash } from "../src/server.js";
import { createBackupWith, encryptItemWithNonce, sealWithNonce } from "../src/testing.js";
import { hex, toHex, vectors } from "./vectors.js";

async function exportRaw(key: CryptoKey): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
}

describe("Argon2id", () => {
  it.each(vectors.argon2id.reference)("reference KAT $note", async (v) => {
    const out = await argon2idRaw(utf8(v.passwordUtf8), utf8(v.saltUtf8), v, v.length);
    expect(toHex(out)).toBe(v.hashHex);
  });
});

describe("HKDF-SHA256", () => {
  it.each(vectors.hkdf)("$info", async (v) => {
    expect(toHex(await hkdfSha256(hex(v.ikmHex), v.info, v.length ?? 32))).toBe(v.okmHex);
  });
});

describe("key hierarchy", () => {
  for (const v of vectors.keyHierarchy) {
    describe(v.name, () => {
      const salt = fromBase64Url(v.kdf.saltB64);

      it("normalises the password with NFKC", () => {
        expect(toHex(normalizePassword(v.password))).toBe(v.normalizedPasswordHex);
      });

      it("derives masterKey, authKey and kek", async () => {
        const mk = await deriveMasterKey(v.password, salt, v.kdf.params);
        expect(toHex(mk)).toBe(v.masterKeyHex);
        expect(toHex(await hkdfSha256(mk, INFO_AUTH))).toBe(v.authKeyHex);
        expect(toHex(await hkdfSha256(mk, INFO_KEK))).toBe(v.kekHex);
      });

      it("deriveLoginKeys produces the same authKey and a kek that unwraps the vault key", async () => {
        const { authKey, kek } = await deriveLoginKeys(v.password, salt, v.kdf.params);
        expect(toBase64Url(authKey)).toBe(v.authKeyB64);
        expect(kek.extractable).toBe(false);
        const vk = await unwrapVaultKey(kek, v.wrappedVaultKey, v.userId, { extractable: true });
        expect(await exportRaw(vk)).toBe(v.vaultKeyHex);
        const nonExtractable = await unwrapVaultKey(kek, v.wrappedVaultKey, v.userId);
        expect(nonExtractable.extractable).toBe(false);
      });

      it("wraps the vault key byte-identically", async () => {
        const kek = await importAesKey(hex(v.kekHex));
        const wrapped = await sealWithNonce(
          kek,
          hex(v.vaultKeyHex),
          ctx.vaultKey(v.userId),
          hex(v.wrapNonceHex),
        );
        expect(wrapped).toBe(v.wrappedVaultKey);
        expect(fromBase64Url(wrapped)).toHaveLength(61);
      });

      it("rejects the wrapped key under another user id", async () => {
        const kek = await importAesKey(hex(v.kekHex), { usages: ["unwrapKey"] });
        await expect(
          unwrapVaultKey(kek, v.wrappedVaultKey, "0192d5f0-6a3c-7c1e-9b2a-000000000002"),
        ).rejects.toMatchObject({ code: "DECRYPT_FAILED" });
      });

      it("computes the server authHash (PBKDF2)", async () => {
        const authSalt = fromBase64Url(v.authSaltB64);
        const hash = await computeAuthHash(hex(v.authKeyHex), authSalt);
        expect(toBase64Url(hash)).toBe(v.authHashB64);
        expect(await verifyAuthHash(hex(v.authKeyHex), authSalt, hash)).toBe(true);
        const wrong = hex(v.authKeyHex);
        wrong[0] = (wrong[0] ?? 0) ^ 1;
        expect(await verifyAuthHash(wrong, authSalt, hash)).toBe(false);
      });
    });
  }
});

describe("fake prelogin salt", () => {
  it.each(vectors.fakeSalt.cases)("$email", async (c) => {
    const salt = await fakeSalt(fromBase64Url(vectors.fakeSalt.secretB64), c.email);
    expect(toBase64Url(salt)).toBe(c.saltB64);
  });
});

describe("recovery key", () => {
  for (const v of vectors.recovery) {
    it(v.name, async () => {
      const key = hex(v.recoveryKeyHex);
      expect(recoveryKeyToMnemonic(key)).toBe(v.mnemonic);
      expect(
        toHex(mnemonicToRecoveryKey(`  ${v.mnemonic.toUpperCase().replace(/ /g, "  \n")} `)),
      ).toBe(v.recoveryKeyHex);
      expect(toHex(await hkdfSha256(key, INFO_RECOVERY_KEK))).toBe(v.recoveryKekHex);
      expect(toHex(await hkdfSha256(key, INFO_RECOVERY_AUTH))).toBe(v.recoveryAuthHex);
      const { recoveryAuth, recoveryKek } = await deriveRecoveryKeys(key);
      expect(toHex(recoveryAuth)).toBe(v.recoveryAuthHex);
      const authHash = await computeAuthHash(recoveryAuth, fromBase64Url(v.recoveryAuthSaltB64));
      expect(toBase64Url(authHash)).toBe(v.recoveryAuthHashB64);
      const vk = await unwrapVaultKeyWithRecovery(
        recoveryKek,
        v.recoveryWrappedVaultKey,
        v.userId,
        {
          extractable: true,
        },
      );
      expect(await exportRaw(vk)).toBe(v.vaultKeyHex);
      const rawKek = await importAesKey(hex(v.recoveryKekHex));
      expect(
        await sealWithNonce(
          rawKek,
          hex(v.vaultKeyHex),
          ctx.recoveryVaultKey(v.userId),
          hex(v.wrapNonceHex),
        ),
      ).toBe(v.recoveryWrappedVaultKey);
    });
  }

  it("rejects a bad checksum or wrong word count", () => {
    const words = vectors.recovery[0]?.mnemonic.split(" ") ?? [];
    const swapped = [...words];
    [swapped[0], swapped[1]] = [swapped[1] ?? "", swapped[0] ?? ""];
    expect(() => mnemonicToRecoveryKey(swapped.join(" "))).toThrow(
      expect.objectContaining({ code: "INVALID_MNEMONIC" }) as Error,
    );
    expect(() => mnemonicToRecoveryKey(words.slice(0, 12).join(" "))).toThrow(
      expect.objectContaining({ code: "INVALID_MNEMONIC" }) as Error,
    );
    expect(() =>
      mnemonicToRecoveryKey(words.map((w, i) => (i === 3 ? "notaword" : w)).join(" ")),
    ).toThrow(expect.objectContaining({ code: "INVALID_MNEMONIC" }) as Error);
  });
});

describe("canonical JSON + padding", () => {
  it.each(vectors.padding)("$name", (v) => {
    expect(canonicalJson(v.value)).toBe(v.canonicalJson);
    const padded = padPlaintext(utf8(v.canonicalJson));
    expect(padded).toHaveLength(v.paddedLength);
    expect(toHex(padded)).toBe(v.paddedHex);
    expect(new TextDecoder().decode(unpadPlaintext(padded))).toBe(v.canonicalJson);
  });
});

/** The items section is encrypted with recovery[*].vaultKeyHex. */
const VAULT_KEY_HEX = vectors.recovery[0]?.vaultKeyHex ?? "";

describe("item envelopes", () => {
  for (const v of vectors.items) {
    describe(v.name, () => {
      const ref = { userId: v.userId, itemId: v.itemId, kind: v.kind };

      it("canonical JSON and padding", () => {
        expect(canonicalJson(v.plaintext)).toBe(v.canonicalJson);
        expect(ctx.item(v.userId, v.itemId, v.kind)).toBe(v.aad);
        expect(toHex(padPlaintext(utf8(v.canonicalJson)))).toBe(v.paddedHex);
      });

      it("encrypts byte-identically with the fixed nonce", async () => {
        const key = await importAesKey(hex(VAULT_KEY_HEX));
        expect(await encryptItemWithNonce(key, ref, v.plaintext, hex(v.nonceHex))).toBe(v.envelope);
      });

      it("decrypts and validates", async () => {
        const key = await importAesKey(hex(VAULT_KEY_HEX));
        const value = await decryptItem(key, ref, v.envelope);
        expect(value).toEqual(v.plaintext);
        if (v.kind === "token") expect(validateTokenItem(value)).toEqual(v.plaintext);
        if (v.kind === "folder") expect(validateFolderItem(value)).toEqual(v.plaintext);
      });
    });
  }
});

describe("tamper cases must fail", () => {
  it.each(vectors.tamper)("$name", async (v) => {
    const key = await importAesKey(hex(v.keyHex));
    const ref = { userId: v.userId, itemId: v.itemId, kind: v.kind as "token" };
    await expect(decryptItem(key, ref, v.envelope)).rejects.toMatchObject({ code: v.error });
  });
});

describe("invalid envelopes are rejected before decryption", () => {
  it.each(vectors.invalidEnvelopes)("$name", async (v) => {
    const key = await importAesKey(new Uint8Array(32));
    await expect(open(key, v.envelope, "x")).rejects.toMatchObject({ code: v.error });
  });
});

describe("KDF parameter policy", () => {
  it.each(vectors.kdfParamsRejected)("$name", async (v) => {
    const salt = fromBase64Url(v.saltB64);
    expect(() => validateKdfParams(v.alg, v.params, salt)).toThrow(
      expect.objectContaining({ code: "KDF_PARAMS_REJECTED" }) as Error,
    );
    await expect(deriveMasterKey("pw", salt, v.params, v.alg)).rejects.toMatchObject({
      code: "KDF_PARAMS_REJECTED",
    });
  });
});

describe("encrypted backup", () => {
  for (const v of vectors.backup.cases) {
    describe(v.name, () => {
      it("binds the salt into the AAD", () => {
        expect(ctx.backup(hex(v.saltHex))).toBe(v.aad);
      });

      it("creates a byte-identical file with the fixed salt and nonce", async () => {
        expect(
          await createBackupWith(v.password, v.contents, hex(v.saltHex), hex(v.nonceHex)),
        ).toBe(v.file);
      });

      it("opens to the original contents", async () => {
        expect(await openBackup(v.password, v.file)).toEqual(v.contents);
      });
    });
  }

  it.each(vectors.backup.rejected)("rejects $name", async (v) => {
    await expect(openBackup(v.password, v.file)).rejects.toMatchObject({ code: v.error });
  });
});
