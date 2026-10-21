export { constantTimeEqual, fromBase64Url, toBase64Url } from "@zk2fa/crypto/server";

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array<ArrayBuffer>> {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", input));
}

/** UUIDv7 (RFC 9562): 48-bit ms timestamp, version 7, variant 10, 74 random bits. */
export function uuidv7(now: number = Date.now()): string {
  const b = randomBytes(16);
  let ts = now;
  for (let i = 5; i >= 0; i--) {
    b[i] = ts % 256;
    ts = Math.floor(ts / 256);
  }
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x70;
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
