import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const path = fileURLToPath(new URL("../../../spec/test-vectors.json", import.meta.url));

interface Kdf {
  alg: string;
  version: number;
  params: { m: number; t: number; p: number };
  saltB64: string;
}

export interface CryptoVectors {
  argon2id: {
    reference: {
      passwordUtf8: string;
      saltUtf8: string;
      m: number;
      t: number;
      p: number;
      length: number;
      hashHex: string;
    }[];
  };
  hkdf: { ikmHex: string; info: string; length?: number; okmHex: string }[];
  keyHierarchy: {
    name: string;
    email: string;
    password: string;
    normalizedPasswordHex: string;
    kdf: Kdf;
    userId: string;
    masterKeyHex: string;
    authKeyHex: string;
    kekHex: string;
    authKeyB64: string;
    authSaltB64: string;
    authHashB64: string;
    vaultKeyHex: string;
    wrapNonceHex: string;
    wrappedVaultKey: string;
  }[];
  fakeSalt: { secretB64: string; cases: { email: string; normalized: string; saltB64: string }[] };
  recovery: {
    name: string;
    recoveryKeyHex: string;
    mnemonic: string;
    recoveryKekHex: string;
    recoveryAuthHex: string;
    recoveryAuthSaltB64: string;
    recoveryAuthHashB64: string;
    userId: string;
    vaultKeyHex: string;
    wrapNonceHex: string;
    recoveryWrappedVaultKey: string;
  }[];
  padding: {
    name: string;
    value: unknown;
    canonicalJson: string;
    jsonLength: number;
    paddedLength: number;
    paddedHex: string;
  }[];
  items: {
    name: string;
    userId: string;
    itemId: string;
    kind: "token" | "folder" | "settings";
    plaintext: Record<string, unknown>;
    aad: string;
    canonicalJson: string;
    paddedLength: number;
    paddedHex: string;
    nonceHex: string;
    envelope: string;
  }[];
  tamper: {
    name: string;
    keyHex: string;
    userId: string;
    itemId: string;
    kind: string;
    envelope: string;
    error: string;
  }[];
  invalidEnvelopes: { name: string; envelope: string; error: string }[];
  kdfParamsRejected: {
    name: string;
    alg: string;
    params: { m: number; t: number; p: number };
    saltB64: string;
  }[];
}

export const vectors = JSON.parse(readFileSync(path, "utf8")) as CryptoVectors;

export function hex(s: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(Buffer.from(s, "hex"));
}

export function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}
