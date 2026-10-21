import { fromBase64Url, toBase64Url } from "./encoding.js";

const cache = new Map<string, Promise<CryptoKey>>();

function key(secretB64: string): Promise<CryptoKey> {
  let k = cache.get(secretB64);
  if (k === undefined) {
    const raw = fromBase64Url(secretB64);
    if (raw.length < 32) throw new Error("HMAC secret must be at least 32 bytes");
    k = crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    cache.set(secretB64, k);
  }
  return k;
}

/** HMAC-SHA256 truncated to 16 bytes, base64url. Used to pseudonymise IPs and e-mails in counters and logs. */
export async function pseudonym(secretB64: string, value: string): Promise<string> {
  const mac = await crypto.subtle.sign(
    "HMAC",
    await key(secretB64),
    new TextEncoder().encode(value),
  );
  return toBase64Url(new Uint8Array(mac).slice(0, 16));
}
