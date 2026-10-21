import type { z } from "zod";
import * as S from "./schemas.js";

export interface RouteDef {
  method: "get" | "post" | "delete";
  path: string;
  summary: string;
  auth: boolean;
  body?: z.ZodType;
  query?: z.ZodObject;
  params?: z.ZodObject;
  response: z.ZodType | null;
  status: 200 | 201 | 204;
}

/** The API contract (prefix /api/v1). The Worker routes and the OpenAPI document are both built from this table. */
export const ROUTES = {
  config: {
    method: "get",
    path: "/config",
    summary: "Public client configuration",
    auth: false,
    response: S.ConfigResponse,
    status: 200,
  },
  time: {
    method: "get",
    path: "/time",
    summary: "Server UNIX time in ms for clock-drift correction",
    auth: false,
    response: S.TimeResponse,
    status: 200,
  },
  prelogin: {
    method: "post",
    path: "/auth/prelogin",
    summary: "KDF params and salt (deterministic fake for unknown e-mail)",
    auth: false,
    body: S.PreloginRequest,
    response: S.PreloginResponse,
    status: 200,
  },
  register: {
    method: "post",
    path: "/auth/register",
    summary: "Create an account with client-side derived keys",
    auth: false,
    body: S.RegisterRequest,
    response: S.SessionResponse,
    status: 201,
  },
  login: {
    method: "post",
    path: "/auth/login",
    summary: "Log in with authKey; returns tokens and the wrapped vault key",
    auth: false,
    body: S.LoginRequest,
    response: S.SessionResponse,
    status: 200,
  },
  refresh: {
    method: "post",
    path: "/auth/refresh",
    summary: "Rotate the refresh token; reuse revokes the session family",
    auth: false,
    body: S.RefreshRequest,
    response: S.RefreshResponse,
    status: 200,
  },
  logout: {
    method: "post",
    path: "/auth/logout",
    summary: "Revoke the current device session",
    auth: true,
    response: null,
    status: 204,
  },
  changePassword: {
    method: "post",
    path: "/auth/change-password",
    summary: "Atomically replace auth hash and wrapped vault key; revokes other sessions",
    auth: true,
    body: S.ChangePasswordRequest,
    response: S.SessionResponse,
    status: 200,
  },
  recoverStart: {
    method: "post",
    path: "/auth/recover/start",
    summary: "Prove the recovery key and fetch the recovery-wrapped vault key",
    auth: false,
    body: S.RecoverStartRequest,
    response: S.RecoverStartResponse,
    status: 200,
  },
  recover: {
    method: "post",
    path: "/auth/recover",
    summary: "Set a new password and recovery key using the old recovery key",
    auth: false,
    body: S.RecoverRequest,
    response: S.SessionResponse,
    status: 200,
  },
  sync: {
    method: "get",
    path: "/sync",
    summary: "Items with revision > since, including tombstones",
    auth: true,
    query: S.SyncQuery,
    response: S.SyncResponse,
    status: 200,
  },
  push: {
    method: "post",
    path: "/sync/push",
    summary: "Batch upserts/deletes with per-item baseRevision; returns conflicts",
    auth: true,
    body: S.PushRequest,
    response: S.PushResponse,
    status: 200,
  },
  devices: {
    method: "get",
    path: "/devices",
    summary: "List active sessions",
    auth: true,
    response: S.DevicesResponse,
    status: 200,
  },
  revokeDevice: {
    method: "delete",
    path: "/devices/{id}",
    summary: "Revoke a session",
    auth: true,
    response: null,
    status: 204,
  },
  deleteAccount: {
    method: "delete",
    path: "/account",
    summary: "Hard-delete the account; requires a fresh authKey",
    auth: true,
    body: S.DeleteAccountRequest,
    response: null,
    status: 204,
  },
} as const satisfies Record<string, RouteDef>;

export const API_PREFIX = "/api/v1";
