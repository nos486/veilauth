import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import {
  encryptItem,
  importAesKey,
  randomBytes,
  toBase64Url,
  wrapVaultKey,
  wrapVaultKeyForRecovery,
} from "@zk2fa/crypto";
import type { ApiError, Kdf, RegisterRequest, SessionResponse } from "@zk2fa/shared";
import worker from "../src/index.js";
import { uuidv7 } from "../src/lib/encoding.js";

export { env };

let ipCounter = 0;
/** Each test client gets its own IP so per-IP limits do not leak between tests. */
export function freshIp(): string {
  ipCounter++;
  return `198.51.${Math.floor(ipCounter / 250)}.${ipCounter % 250}`;
}

export interface CallOptions {
  method?: string;
  body?: unknown;
  token?: string;
  ip?: string;
  headers?: Record<string, string>;
}

export async function call(path: string, opts: CallOptions = {}): Promise<Response> {
  const headers = new Headers(opts.headers);
  headers.set("cf-connecting-ip", opts.ip ?? "203.0.113.1");
  if (opts.body !== undefined) headers.set("content-type", "application/json");
  if (opts.token !== undefined) headers.set("authorization", `Bearer ${opts.token}`);
  const req = new Request(`https://veilauth.test${path}`, {
    method: opts.method ?? (opts.body === undefined ? "GET" : "POST"),
    headers,
    ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
  });
  const ctx = createExecutionContext();
  const res = await worker.fetch(req, env, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

export async function json<T>(res: Response): Promise<T> {
  return await res.json();
}

export async function expectError(
  res: Response,
  status: number,
  code: ApiError["code"],
): Promise<ApiError> {
  const body = await json<ApiError>(res);
  if (res.status !== status || body.code !== code) {
    throw new Error(`expected ${status} ${code}, got ${res.status} ${body.code}`);
  }
  return body;
}

export const KDF_PARAMS = { m: 65536, t: 3, p: 1 };

/** A simulated client. Argon2id is skipped (keys are random) — the server cannot tell the difference. */
export class TestClient {
  readonly userId = uuidv7();
  readonly deviceId = uuidv7();
  readonly ip = freshIp();
  email: string;
  authKey = toBase64Url(randomBytes(32));
  recoveryAuth = toBase64Url(randomBytes(32));
  kdf: Kdf = {
    alg: "argon2id",
    version: 1,
    params: KDF_PARAMS,
    salt: toBase64Url(randomBytes(16)),
  };
  readonly vaultKeyRaw = randomBytes(32);
  session: SessionResponse | undefined;

  constructor(email?: string) {
    this.email = email ?? `user-${this.userId.slice(-12)}@example.com`;
  }

  get token(): string {
    if (this.session === undefined) throw new Error("not logged in");
    return this.session.accessToken;
  }

  async registerBody(): Promise<RegisterRequest> {
    const kek = await importAesKey(randomBytes(32));
    const rkek = await importAesKey(randomBytes(32));
    return {
      userId: this.userId,
      email: this.email,
      kdf: this.kdf,
      authKey: this.authKey,
      wrappedVaultKey: await wrapVaultKey(kek, this.vaultKeyRaw, this.userId),
      recovery: {
        authKey: this.recoveryAuth,
        wrappedVaultKey: await wrapVaultKeyForRecovery(rkek, this.vaultKeyRaw, this.userId),
      },
      device: { id: this.deviceId, platform: "web", nameEnc: null },
    };
  }

  async register(): Promise<SessionResponse> {
    const res = await call("/api/v1/auth/register", {
      body: await this.registerBody(),
      ip: this.ip,
    });
    if (res.status !== 201) throw new Error(`register failed: ${res.status} ${await res.text()}`);
    this.session = await json<SessionResponse>(res);
    return this.session;
  }

  async login(deviceId: string = this.deviceId, ip: string = this.ip): Promise<Response> {
    return call("/api/v1/auth/login", {
      body: {
        email: this.email,
        authKey: this.authKey,
        device: { id: deviceId, platform: "android", nameEnc: null },
      },
      ip,
    });
  }

  async vaultKey(): Promise<CryptoKey> {
    return importAesKey(this.vaultKeyRaw);
  }

  async blob(
    itemId: string,
    plaintext: object,
    kind: "token" | "folder" | "settings" = "token",
  ): Promise<string> {
    return encryptItem(await this.vaultKey(), { userId: this.userId, itemId, kind }, plaintext);
  }
}

/** A well-formed padded envelope with random content (the server cannot distinguish it from a real one). */
export function fakeBlob(buckets = 1): string {
  const raw = randomBytes(1 + 12 + 256 * buckets + 16);
  raw[0] = 1;
  return toBase64Url(raw);
}

export { uuidv7 };
