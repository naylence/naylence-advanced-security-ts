import { compactVerify, importJWK, importSPKI } from "jose";
import type { KeyProvider } from "@naylence/runtime";
import type { KeyRecord } from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";

import type { AFTClaims, AFTHeader } from "./aft-model.js";
import { base64UrlDecode, utf8Decode } from "./aft-utils.js";
import { StickinessMode } from "./stickiness-mode.js";

const logger = getLogger("naylence.fame.stickiness.aft_verifier");

export type TrustLevel = "trusted" | "low-trust" | "untrusted";

export interface AFTVerificationResult {
  readonly valid: boolean;
  readonly sid?: string | undefined;
  readonly exp?: number | undefined;
  readonly scope?: string | null | undefined;
  readonly trustLevel: TrustLevel;
  readonly error?: string | undefined;
  readonly clientSid?: string | null | undefined;
}

type ImportedJwkKey = Awaited<ReturnType<typeof importJWK>>;
type ImportedSpkiKey = Awaited<ReturnType<typeof importSPKI>>;
type VerificationKey = ImportedJwkKey | ImportedSpkiKey;

export interface AFTVerifier {
  readonly securityLevel: StickinessMode;
  verify(
    token: string,
    expectedSid?: string | null,
  ): Promise<AFTVerificationResult>;
}

interface DecodedToken {
  header: AFTHeader;
  claims: AFTClaims;
}

function decodeToken(token: string): DecodedToken | null {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }

  const [headerB64, payloadB64] = parts;
  if (!headerB64 || !payloadB64) {
    return null;
  }

  try {
    const headerJson = utf8Decode(base64UrlDecode(headerB64));
    const payloadJson = utf8Decode(base64UrlDecode(payloadB64));

    const headerData = JSON.parse(headerJson) as Record<string, unknown>;
    const payloadData = JSON.parse(payloadJson) as Record<string, unknown>;

    const header: AFTHeader = {
      alg: String(headerData.alg ?? ""),
      kid: String(headerData.kid ?? ""),
    };

    const claims: AFTClaims = {
      sid: String(payloadData.sid ?? ""),
      exp: Number(payloadData.exp ?? 0),
    };

    if (typeof payloadData.scp === "string" && payloadData.scp.length > 0) {
      claims.scp = payloadData.scp;
    }

    if (
      typeof payloadData.client_sid === "string" &&
      payloadData.client_sid.length > 0
    ) {
      claims.client_sid = payloadData.client_sid;
    }

    return { header, claims };
  } catch (error) {
    logger.debug("aft_decoding_failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

abstract class BaseAFTVerifier implements AFTVerifier {
  protected readonly defaultTtlSec: number;

  protected constructor(defaultTtlSec: number = 30) {
    this.defaultTtlSec = defaultTtlSec;
  }

  public abstract get securityLevel(): StickinessMode;

  protected abstract verifySignature(
    token: string,
    header: AFTHeader,
    claims: AFTClaims,
  ): Promise<boolean>;

  public async verify(
    token: string,
    expectedSid?: string | null,
  ): Promise<AFTVerificationResult> {
    const decoded = decodeToken(token);
    if (!decoded) {
      return {
        valid: false,
        trustLevel: "untrusted",
        error: "Invalid token format - expected 3 parts",
      };
    }

    const { header, claims } = decoded;

    if (!header.alg || !header.kid) {
      return {
        valid: false,
        trustLevel: "untrusted",
        error: "Missing algorithm or key ID",
      };
    }

    if (!claims.sid || !Number.isFinite(claims.exp)) {
      return {
        valid: false,
        trustLevel: "untrusted",
        error: "Token missing required claims",
      };
    }

    const currentTime = Math.floor(Date.now() / 1000);
    if (claims.exp <= currentTime) {
      return {
        valid: false,
        sid: claims.sid,
        exp: claims.exp,
        scope: claims.scp ?? undefined,
        clientSid: claims.client_sid ?? undefined,
        trustLevel: "untrusted",
        error: "Token expired",
      };
    }

    if (expectedSid && claims.sid !== expectedSid) {
      return {
        valid: false,
        sid: claims.sid,
        exp: claims.exp,
        scope: claims.scp ?? undefined,
        clientSid: claims.client_sid ?? undefined,
        trustLevel: "untrusted",
        error: `SID mismatch: expected ${expectedSid}, got ${claims.sid}`,
      };
    }

    let signatureValid = false;
    try {
      signatureValid = await this.verifySignature(token, header, claims);
    } catch (error) {
      logger.debug("aft_signature_verification_failed", {
        kid: header.kid,
        algorithm: header.alg,
        error: error instanceof Error ? error.message : String(error),
      });
      signatureValid = false;
    }

    if (!signatureValid) {
      return {
        valid: false,
        sid: claims.sid,
        exp: claims.exp,
        scope: claims.scp ?? undefined,
        clientSid: claims.client_sid ?? undefined,
        trustLevel: "untrusted",
        error: "Invalid signature",
      };
    }

    const trustLevel: TrustLevel =
      header.alg === "none" ? "low-trust" : "trusted";

    return {
      valid: true,
      sid: claims.sid,
      exp: claims.exp,
      scope: claims.scp ?? undefined,
      clientSid: claims.client_sid ?? undefined,
      trustLevel,
    };
  }
}

export class StrictAFTVerifier extends BaseAFTVerifier {
  private readonly keyProvider: KeyProvider;

  public constructor(keyProvider: KeyProvider, defaultTtlSec: number = 30) {
    super(defaultTtlSec);
    this.keyProvider = keyProvider;
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.STRICT;
  }

  protected async verifySignature(
    token: string,
    header: AFTHeader,
  ): Promise<boolean> {
    if (header.alg === "none") {
      return false;
    }

    let keyRecord: KeyRecord;
    try {
      keyRecord = await this.keyProvider.getKey(header.kid);
    } catch (error) {
      logger.debug("aft_public_key_missing", {
        kid: header.kid,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }

    const key = await resolveVerificationKey(keyRecord, header.alg);
    if (!key) {
      return false;
    }

    try {
      const { protectedHeader } = await compactVerify(token, key);
      return protectedHeader.alg === header.alg;
    } catch (error) {
      logger.debug("aft_jws_verification_failed", {
        kid: header.kid,
        algorithm: header.alg,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }
}

export class SignedOptionalAFTVerifier extends BaseAFTVerifier {
  private readonly keyProvider: KeyProvider | null;

  public constructor(
    keyProvider: KeyProvider | null,
    defaultTtlSec: number = 30,
  ) {
    super(defaultTtlSec);
    this.keyProvider = keyProvider;
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.SIGNED_OPTIONAL;
  }

  protected async verifySignature(
    token: string,
    header: AFTHeader,
  ): Promise<boolean> {
    if (header.alg === "none") {
      return true;
    }

    if (!this.keyProvider) {
      return false;
    }

    let keyRecord: KeyRecord;
    try {
      keyRecord = await this.keyProvider.getKey(header.kid);
    } catch (error) {
      logger.debug("aft_public_key_missing", {
        kid: header.kid,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }

    const key = await resolveVerificationKey(keyRecord, header.alg);
    if (!key) {
      return false;
    }

    try {
      const { protectedHeader } = await compactVerify(token, key);
      return protectedHeader.alg === header.alg;
    } catch (error) {
      logger.debug("aft_jws_verification_failed", {
        kid: header.kid,
        algorithm: header.alg,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }
}

export class SidOnlyAFTVerifier extends BaseAFTVerifier {
  public constructor(defaultTtlSec: number = 30) {
    super(defaultTtlSec);
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.SID_ONLY;
  }

  public async verify(
    _token: string,
    _expectedSid?: string | null,
  ): Promise<AFTVerificationResult> {
    return {
      valid: false,
      trustLevel: "untrusted",
      error: "SID-only mode ignores AFTs",
    };
  }

  protected async verifySignature(): Promise<boolean> {
    return false;
  }
}

async function resolveVerificationKey(
  keyRecord: KeyRecord,
  algorithm: string,
): Promise<VerificationKey | null> {
  const jwkCandidate = keyRecord as unknown as Record<string, unknown>;

  if (typeof jwkCandidate.kty === "string") {
    try {
      const key = await importJWK(
        jwkCandidate as unknown as JsonWebKey,
        algorithm,
      );
      return key as VerificationKey;
    } catch (error) {
      logger.debug("aft_jwk_import_failed", {
        kid: keyRecord.kid,
        algorithm,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  let pem: string | null = null;
  const record = keyRecord as Record<string, unknown>;
  if (typeof record.public_key_pem === "string") {
    pem = record.public_key_pem;
  } else if (typeof record.publicKeyPem === "string") {
    pem = record.publicKeyPem;
  }

  if (typeof pem === "string" && pem.length > 0) {
    try {
      const key = await importSPKI(pem, algorithm);
      return key as VerificationKey;
    } catch (error) {
      logger.debug("aft_spki_import_failed", {
        kid: keyRecord.kid,
        algorithm,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  logger.debug("aft_verification_key_unavailable", {
    kid: keyRecord.kid,
    algorithm,
  });
  return null;
}

export interface CreateAftVerifierOptions {
  securityLevel: StickinessMode;
  keyProvider: KeyProvider | null;
  defaultTtlSec?: number;
}

export function createAftVerifier(
  options: CreateAftVerifierOptions,
): AFTVerifier {
  const { securityLevel, keyProvider, defaultTtlSec = 30 } = options;

  switch (securityLevel) {
    case StickinessMode.STRICT:
      if (!keyProvider) {
        throw new Error("StrictAFTVerifier requires a KeyProvider instance");
      }
      return new StrictAFTVerifier(keyProvider, defaultTtlSec);
    case StickinessMode.SIGNED_OPTIONAL:
      return new SignedOptionalAFTVerifier(keyProvider, defaultTtlSec);
    case StickinessMode.SID_ONLY:
      return new SidOnlyAFTVerifier(defaultTtlSec);
    default:
      throw new Error(`Unknown security level: ${securityLevel}`);
  }
}
