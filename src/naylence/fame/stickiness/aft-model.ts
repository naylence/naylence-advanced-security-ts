import type { StickinessMode } from "./stickiness-mode.js";

export interface AFTClaims {
  sid: string;
  exp: number;
  scp?: string | null;
  client_sid?: string | null;
}

export interface AFTHeader {
  alg: string;
  kid: string;
}

export interface AFTPayload {
  header: AFTHeader;
  claims: AFTClaims;
}

export function isSignedAft(payload: AFTPayload | { header: AFTHeader }): boolean {
  return payload.header.alg !== "none";
}

export function sanitizeStickinessScope(scope?: string | null): string | undefined {
  if (!scope) {
    return undefined;
  }

  const normalized = scope.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }

  if (normalized === "node" || normalized === "flow" || normalized === "sess") {
    return normalized;
  }

  return undefined;
}

export function serializeAftHeader(header: AFTHeader): string {
  return JSON.stringify({
    alg: header.alg,
    kid: header.kid,
  });
}

export function serializeAftClaims(claims: AFTClaims): string {
  const payload: Record<string, unknown> = {
    sid: claims.sid,
    exp: claims.exp,
  };

  if (typeof claims.scp === "string" && claims.scp.length > 0) {
    payload.scp = claims.scp;
  }

  if (typeof claims.client_sid === "string" && claims.client_sid.length > 0) {
    payload.client_sid = claims.client_sid;
  }

  return JSON.stringify(payload);
}

export interface CreateAftPayloadOptions {
  sid: string;
  ttlSeconds: number;
  kid: string;
  algorithm: string;
  scope?: string | null;
  clientSid?: string | null;
  now?: () => number;
}

export function createAftPayload(options: CreateAftPayloadOptions): AFTPayload {
  const {
    sid,
    ttlSeconds,
    kid,
    algorithm,
    scope = null,
    clientSid = null,
    now = () => Math.floor(Date.now() / 1000),
  } = options;

  const exp = now() + Math.max(0, Math.floor(ttlSeconds));

  const sanitizedScope = sanitizeStickinessScope(scope);
  const header: AFTHeader = { alg: algorithm, kid };
  const claims: AFTClaims = {
    sid,
    exp,
    ...(sanitizedScope ? { scp: sanitizedScope } : {}),
    ...(typeof clientSid === "string" && clientSid.length > 0
      ? { client_sid: clientSid }
      : {}),
  };

  return { header, claims };
}

export function describeSecurityLevel(mode: StickinessMode): string {
  return mode;
}
