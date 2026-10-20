import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const path = fileURLToPath(new URL("../../../spec/test-vectors.json", import.meta.url));

export interface ParsedVector {
  type: string;
  issuer: string;
  account: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
  counter: number;
}

export interface OtpVectors {
  hotp: {
    secretHex: string;
    counter: number;
    digits: number;
    algorithm: "SHA1" | "SHA256" | "SHA512";
    code: string;
  }[];
  totp: {
    secretHex: string;
    timeMs: number;
    period: number;
    digits: number;
    algorithm: "SHA1" | "SHA256" | "SHA512";
    code: string;
  }[];
  steam: { secretB32: string; timeMs: number; code: string }[];
  otpauth: ({ uri: string; expected: ParsedVector } | { uri: string; error: string })[];
  migration: {
    name: string;
    uris: string[];
    batchId?: number;
    entries?: unknown[];
    error?: string;
  }[];
}

export const vectors = (JSON.parse(readFileSync(path, "utf8")) as { otp: OtpVectors }).otp;

export function hex(s: string): Uint8Array {
  return Uint8Array.from(Buffer.from(s, "hex"));
}
