import { describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, type ClientErrorCode } from "../src/api/client";

const KEY = "A".repeat(43);

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function setup(handler: (path: string, init: RequestInit) => Response | Promise<Response>) {
  let refreshToken: string | null = KEY;
  const ended: ClientErrorCode[] = [];
  const calls: string[] = [];
  const api = new ApiClient({
    fetch: (input, init) => {
      const path = new URL(input instanceof Request ? input.url : input, "http://x").pathname;
      calls.push(path);
      return Promise.resolve(handler(path, init ?? {}));
    },
    tokens: {
      loadRefreshToken: () => Promise.resolve(refreshToken),
      saveRefreshToken: (t) => {
        refreshToken = t;
        return Promise.resolve();
      },
    },
    onSessionEnded: (c) => ended.push(c),
    withLock: (_n, fn) => fn(),
  });
  return { api, ended, calls, refresh: () => refreshToken };
}

const devices = { devices: [] };

describe("ApiClient", () => {
  it("refreshes once for concurrent requests and stores the rotated refresh token", async () => {
    let refreshes = 0;
    const s = setup((path, init) => {
      if (path === "/api/v1/auth/refresh") {
        refreshes++;
        expect(JSON.parse(init.body as string)).toEqual({ refreshToken: KEY });
        return jsonResponse(200, {
          accessToken: "jwt",
          accessTokenExpiresAt: Date.now() + 900_000,
          refreshToken: "B".repeat(43),
        });
      }
      expect((init.headers as Record<string, string>).authorization).toBe("Bearer jwt");
      return jsonResponse(200, devices);
    });
    await Promise.all([s.api.devices(), s.api.devices(), s.api.devices()]);
    expect(refreshes).toBe(1);
    expect(s.refresh()).toBe("B".repeat(43));
  });

  it("retries once after TOKEN_EXPIRED", async () => {
    let first = true;
    const s = setup((path) => {
      if (path === "/api/v1/auth/refresh")
        return jsonResponse(200, {
          accessToken: "jwt2",
          accessTokenExpiresAt: Date.now() + 900_000,
          refreshToken: KEY,
        });
      if (first) {
        first = false;
        return jsonResponse(401, { code: "TOKEN_EXPIRED", message: "x" });
      }
      return jsonResponse(200, devices);
    });
    s.api.setAccessToken("old", Date.now() + 900_000);
    await expect(s.api.devices()).resolves.toEqual(devices);
    expect(s.calls).toEqual(["/api/v1/devices", "/api/v1/auth/refresh", "/api/v1/devices"]);
  });

  it("ends the session when the refresh token was reused or the session revoked", async () => {
    const s = setup(() => jsonResponse(401, { code: "REFRESH_REUSED", message: "x" }));
    await expect(s.api.devices()).rejects.toMatchObject({ code: "REFRESH_REUSED" });
    expect(s.ended).toEqual(["REFRESH_REUSED"]);

    const r = setup(() => jsonResponse(401, { code: "SESSION_REVOKED", message: "x" }));
    r.api.setAccessToken("jwt", Date.now() + 900_000);
    await expect(r.api.sync(0)).rejects.toMatchObject({ code: "SESSION_REVOKED" });
    expect(r.ended).toEqual(["SESSION_REVOKED"]);
  });

  it("does not end the session for wrong credentials on login", async () => {
    const s = setup(() => jsonResponse(401, { code: "INVALID_CREDENTIALS", message: "x" }));
    await expect(
      s.api.login({
        email: "a@b.c",
        authKey: KEY,
        device: { id: "0", platform: "web", nameEnc: null },
      }),
    ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
    expect(s.ended).toEqual([]);
  });

  it("maps network failures and malformed responses to stable codes", async () => {
    const offline = new ApiClient({
      fetch: () => Promise.reject(new TypeError("Failed to fetch")),
      tokens: {
        loadRefreshToken: () => Promise.resolve(null),
        saveRefreshToken: () => Promise.resolve(),
      },
      onSessionEnded: vi.fn(),
    });
    await expect(offline.time()).rejects.toMatchObject({ code: "NETWORK" });
    const bad = setup(() => jsonResponse(200, { now: "soon" }));
    const err = await bad.api.time().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe("BAD_RESPONSE");
    expect((err as ApiError).message).toBe("BAD_RESPONSE");
  });
});
