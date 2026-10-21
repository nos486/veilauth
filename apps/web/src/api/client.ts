import {
  API_PREFIX,
  type ApiErrorCode,
  ApiError as ApiErrorSchema,
  ConfigResponse,
  DevicesResponse,
  PreloginResponse,
  PushResponse,
  RefreshResponse,
  SessionResponse,
  SyncResponse,
  TimeResponse,
  type ChangePasswordRequest,
  type LoginRequest,
  type PushChange,
  type RegisterRequest,
} from "@zk2fa/shared";
import type { z } from "zod";
import { setClockOffset } from "../lib/time";

export type ClientErrorCode = ApiErrorCode | "NETWORK" | "BAD_RESPONSE";

/** Error from the API (stable `code`) or the network. Never carries request or response bodies. */
export class ApiError extends Error {
  readonly code: ClientErrorCode;
  readonly status: number;
  constructor(code: ClientErrorCode, status: number) {
    super(code);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

/** Codes after which the session cannot continue: the user has to log in again. */
export const SESSION_ENDING_CODES: readonly ClientErrorCode[] = [
  "SESSION_REVOKED",
  "REFRESH_REUSED",
  "UNAUTHORIZED",
];

export interface TokenStore {
  /** latest refresh token, read fresh inside the cross-tab lock */
  loadRefreshToken(): Promise<string | null>;
  saveRefreshToken(token: string): Promise<void>;
}

export type WithLock = <T>(name: string, fn: () => Promise<T>) => Promise<T>;

export interface ApiClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  tokens: TokenStore;
  onSessionEnded: (code: ClientErrorCode) => void;
  /** serialises refreshes across tabs; defaults to the Web Locks API when present */
  withLock?: WithLock;
}

const REFRESH_MARGIN_MS = 30_000;

function defaultLock<T>(name: string, fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && "locks" in navigator) {
    return navigator.locks.request(name, fn) as Promise<T>;
  }
  return fn();
}

interface RequestOptions {
  method: "GET" | "POST" | "DELETE";
  body?: unknown;
  auth: boolean;
}

export class ApiClient {
  private readonly base: string;
  private readonly fetchFn: typeof fetch;
  private readonly tokens: TokenStore;
  private readonly onSessionEnded: (code: ClientErrorCode) => void;
  private readonly withLock: WithLock;
  private accessToken: string | null = null;
  private accessExpiresAt = 0;
  private refreshing: Promise<void> | null = null;

  constructor(options: ApiClientOptions) {
    this.base = (options.baseUrl ?? "") + API_PREFIX;
    this.fetchFn = options.fetch ?? fetch.bind(globalThis);
    this.tokens = options.tokens;
    this.onSessionEnded = options.onSessionEnded;
    this.withLock = options.withLock ?? defaultLock;
  }

  setAccessToken(token: string, expiresAt: number): void {
    this.accessToken = token;
    this.accessExpiresAt = expiresAt;
  }

  clearAccessToken(): void {
    this.accessToken = null;
    this.accessExpiresAt = 0;
  }

  // ------------------------------------------------------------------ public endpoints

  config() {
    return this.json(ConfigResponse, "/config", { method: "GET", auth: false });
  }

  async time(): Promise<number> {
    const sentAt = Date.now();
    const { now } = await this.json(TimeResponse, "/time", { method: "GET", auth: false });
    setClockOffset(sentAt, now, Date.now());
    return now;
  }

  prelogin(email: string) {
    return this.json(PreloginResponse, "/auth/prelogin", {
      method: "POST",
      body: { email },
      auth: false,
    });
  }

  async register(req: RegisterRequest) {
    return this.adopt(
      await this.json(SessionResponse, "/auth/register", {
        method: "POST",
        body: req,
        auth: false,
      }),
    );
  }

  async login(req: LoginRequest) {
    return this.adopt(
      await this.json(SessionResponse, "/auth/login", { method: "POST", body: req, auth: false }),
    );
  }

  // ------------------------------------------------------------------ authenticated endpoints

  async changePassword(req: ChangePasswordRequest) {
    return this.adopt(
      await this.json(SessionResponse, "/auth/change-password", {
        method: "POST",
        body: req,
        auth: true,
      }),
    );
  }

  async logout(): Promise<void> {
    await this.send("/auth/logout", { method: "POST", auth: true });
  }

  sync(since: number) {
    return this.json(SyncResponse, `/sync?since=${String(since)}`, { method: "GET", auth: true });
  }

  push(changes: PushChange[]) {
    return this.json(PushResponse, "/sync/push", {
      method: "POST",
      body: { changes },
      auth: true,
    });
  }

  devices() {
    return this.json(DevicesResponse, "/devices", { method: "GET", auth: true });
  }

  async revokeDevice(id: string): Promise<void> {
    await this.send(`/devices/${encodeURIComponent(id)}`, { method: "DELETE", auth: true });
  }

  async deleteAccount(authKey: string): Promise<void> {
    await this.send("/account", { method: "DELETE", body: { authKey }, auth: true });
  }

  // ------------------------------------------------------------------ plumbing

  private async adopt(session: SessionResponse): Promise<SessionResponse> {
    await this.tokens.saveRefreshToken(session.refreshToken);
    this.setAccessToken(session.accessToken, session.accessTokenExpiresAt);
    return session;
  }

  private async json<S extends z.ZodType>(
    schema: S,
    path: string,
    opts: RequestOptions,
  ): Promise<z.infer<S>> {
    const res = await this.send(path, opts);
    let data: unknown;
    try {
      data = await res.json();
    } catch (e: unknown) {
      if (e instanceof SyntaxError) throw new ApiError("BAD_RESPONSE", res.status);
      throw e;
    }
    const parsed = schema.safeParse(data);
    if (!parsed.success) throw new ApiError("BAD_RESPONSE", res.status);
    return parsed.data;
  }

  private async send(path: string, opts: RequestOptions, retried = false): Promise<Response> {
    if (
      opts.auth &&
      (this.accessToken === null || Date.now() > this.accessExpiresAt - REFRESH_MARGIN_MS)
    ) {
      await this.refresh();
    }
    const headers: Record<string, string> = { accept: "application/json" };
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    if (opts.auth && this.accessToken !== null)
      headers.authorization = `Bearer ${this.accessToken}`;
    let res: Response;
    try {
      res = await this.fetchFn(this.base + path, {
        method: opts.method,
        headers,
        body: opts.body === undefined ? null : JSON.stringify(opts.body),
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch (e: unknown) {
      if (e instanceof TypeError) throw new ApiError("NETWORK", 0);
      throw e;
    }
    if (res.ok) return res;
    const code = await errorCode(res);
    if (opts.auth && code === "TOKEN_EXPIRED" && !retried) {
      this.clearAccessToken();
      return this.send(path, opts, true);
    }
    if (opts.auth && SESSION_ENDING_CODES.includes(code)) this.endSession(code);
    throw new ApiError(code, res.status);
  }

  /** Single-flight refresh, serialised across tabs so a rotated token is never reused. */
  private refresh(): Promise<void> {
    this.refreshing ??= this.withLock("veilauth-refresh", async () => {
      const refreshToken = await this.tokens.loadRefreshToken();
      if (refreshToken === null) {
        this.endSession("UNAUTHORIZED");
        throw new ApiError("UNAUTHORIZED", 401);
      }
      let res: Response;
      try {
        res = await this.fetchFn(`${this.base}/auth/refresh`, {
          method: "POST",
          headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ refreshToken }),
          credentials: "omit",
          cache: "no-store",
          referrerPolicy: "no-referrer",
        });
      } catch (e: unknown) {
        if (e instanceof TypeError) throw new ApiError("NETWORK", 0);
        throw e;
      }
      if (!res.ok) {
        const code = await errorCode(res);
        if (SESSION_ENDING_CODES.includes(code)) this.endSession(code);
        throw new ApiError(code, res.status);
      }
      const parsed = RefreshResponse.safeParse(await res.json());
      if (!parsed.success) throw new ApiError("BAD_RESPONSE", res.status);
      await this.tokens.saveRefreshToken(parsed.data.refreshToken);
      this.setAccessToken(parsed.data.accessToken, parsed.data.accessTokenExpiresAt);
    }).finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  private endSession(code: ClientErrorCode): void {
    this.clearAccessToken();
    this.onSessionEnded(code);
  }
}

async function errorCode(res: Response): Promise<ClientErrorCode> {
  try {
    const parsed = ApiErrorSchema.safeParse(await res.json());
    if (parsed.success) return parsed.data.code;
  } catch (e: unknown) {
    if (!(e instanceof SyntaxError)) throw e;
  }
  if (res.status === 429) return "RATE_LIMITED";
  return res.status >= 500 ? "INTERNAL" : "BAD_RESPONSE";
}
