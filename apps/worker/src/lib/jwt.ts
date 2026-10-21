import { fromBase64Url, toBase64Url } from "./encoding.js";
import { ApiError } from "./errors.js";

/** Access-token claims (build spec §5.4). */
export interface AccessClaims {
  iss: "veilauth";
  sub: string;
  did: string;
  stamp: string;
  iat: number;
  exp: number;
}

interface Ed25519Jwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  d: string;
}

const HEADER = toBase64Url(new TextEncoder().encode(JSON.stringify({ alg: "EdDSA", typ: "JWT" })));
const keyCache = new Map<string, Promise<{ sign: CryptoKey; verify: CryptoKey }>>();

function parseJwk(json: string): Ed25519Jwk {
  const jwk = JSON.parse(json) as Partial<Ed25519Jwk>;
  if (
    jwk.kty !== "OKP" ||
    jwk.crv !== "Ed25519" ||
    typeof jwk.x !== "string" ||
    typeof jwk.d !== "string"
  ) {
    throw new Error("JWT_PRIVATE_JWK must be an Ed25519 private JWK");
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d };
}

function keys(jwkJson: string): Promise<{ sign: CryptoKey; verify: CryptoKey }> {
  let cached = keyCache.get(jwkJson);
  if (cached === undefined) {
    const jwk = parseJwk(jwkJson);
    cached = Promise.all([
      crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]),
      crypto.subtle.importKey(
        "jwk",
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
        { name: "Ed25519" },
        false,
        ["verify"],
      ),
    ]).then(([sign, verify]) => ({ sign, verify }));
    keyCache.set(jwkJson, cached);
  }
  return cached;
}

export async function signAccessToken(jwkJson: string, claims: AccessClaims): Promise<string> {
  const payload = toBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signingInput = `${HEADER}.${payload}`;
  const { sign } = await keys(jwkJson);
  const sig = await crypto.subtle.sign(
    { name: "Ed25519" },
    sign,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${toBase64Url(new Uint8Array(sig))}`;
}

/** Verifies signature, header and expiry. Only the exact EdDSA header this service issues is accepted. */
export async function verifyAccessToken(
  jwkJson: string,
  token: string,
  nowMs: number,
): Promise<AccessClaims> {
  const parts = token.split(".");
  const [header, payload, sig] = parts;
  if (parts.length !== 3 || header !== HEADER || payload === undefined || sig === undefined) {
    throw new ApiError("UNAUTHORIZED");
  }
  let signature: Uint8Array<ArrayBuffer>;
  let claims: Partial<AccessClaims>;
  try {
    signature = fromBase64Url(sig);
    claims = JSON.parse(new TextDecoder().decode(fromBase64Url(payload))) as Partial<AccessClaims>;
  } catch (e: unknown) {
    if (e instanceof Error) throw new ApiError("UNAUTHORIZED");
    throw e;
  }
  const { verify } = await keys(jwkJson);
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    verify,
    signature,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  if (!ok) throw new ApiError("UNAUTHORIZED");
  if (
    claims.iss !== "veilauth" ||
    typeof claims.sub !== "string" ||
    typeof claims.did !== "string" ||
    typeof claims.stamp !== "string" ||
    typeof claims.iat !== "number" ||
    typeof claims.exp !== "number"
  ) {
    throw new ApiError("UNAUTHORIZED");
  }
  if (claims.exp * 1000 <= nowMs) throw new ApiError("TOKEN_EXPIRED");
  return claims as AccessClaims;
}
