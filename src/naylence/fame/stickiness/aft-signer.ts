import { importPKCS8, SignJWT } from "jose";
import { getLogger } from "@naylence/runtime";

import {
  createAftPayload,
  serializeAftClaims,
  serializeAftHeader,
  type AFTPayload,
} from "./aft-model.js";
import { base64UrlEncode } from "./aft-utils.js";
import { StickinessMode } from "./stickiness-mode.js";

const logger = getLogger("naylence.fame.stickiness.aft_signer");

export interface SignAftOptions {
  readonly sid: string;
  readonly ttlSec?: number;
  readonly scope?: string | null;
  readonly clientSid?: string | null;
}

export interface AFTSigner {
  readonly securityLevel: StickinessMode;
  signAft(options: SignAftOptions): Promise<string>;
}

abstract class AbstractAFTSigner implements AFTSigner {
  protected readonly kid: string;
  protected readonly maxTtlSec: number;

  protected constructor(kid: string, maxTtlSec: number = 7200) {
    this.kid = kid;
    this.maxTtlSec = maxTtlSec;
  }

  public abstract get securityLevel(): StickinessMode;

  public abstract signAft(options: SignAftOptions): Promise<string>;

  protected clampTtl(ttlSec: number | undefined): number {
    const requested =
      typeof ttlSec === "number" && Number.isFinite(ttlSec)
        ? Math.max(0, ttlSec)
        : 0;
    if (this.maxTtlSec <= 0) {
      return 0;
    }
    if (requested <= 0) {
      return Math.min(30, this.maxTtlSec);
    }
    return Math.min(Math.floor(requested), this.maxTtlSec);
  }

  protected createPayload(
    options: SignAftOptions,
    algorithm: string,
  ): AFTPayload {
    const ttl = this.clampTtl(options.ttlSec);
    return createAftPayload({
      sid: options.sid,
      kid: this.kid,
      algorithm,
      ttlSeconds: ttl,
      scope: options.scope ?? null,
      clientSid: options.clientSid ?? null,
    });
  }
}

export class UnsignedAFTSigner extends AbstractAFTSigner {
  public constructor(kid: string, maxTtlSec: number = 7200) {
    super(kid, maxTtlSec);
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.SIGNED_OPTIONAL;
  }

  public async signAft(options: SignAftOptions): Promise<string> {
    const payload = this.createPayload(options, "none");

    const headerJson = serializeAftHeader(payload.header);
    const claimsJson = serializeAftClaims(payload.claims);

    const headerB64 = base64UrlEncode(headerJson);
    const payloadB64 = base64UrlEncode(claimsJson);

    return `${headerB64}.${payloadB64}.`;
  }
}

export class NoAFTSigner extends AbstractAFTSigner {
  public constructor() {
    super("none", 0);
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.SID_ONLY;
  }

  public async signAft(): Promise<string> {
    return "";
  }
}

export class SignedAFTSigner extends AbstractAFTSigner {
  private readonly algorithm: string;
  private readonly privateKeyPem: string;
  private cryptoKeyPromise: Promise<CryptoKey> | null = null;

  public constructor(options: {
    kid: string;
    privateKeyPem: string;
    algorithm?: string;
    maxTtlSec?: number;
  }) {
    super(options.kid, options.maxTtlSec ?? 7200);
    this.privateKeyPem = options.privateKeyPem;
    this.algorithm = options.algorithm ?? "EdDSA";
  }

  public get securityLevel(): StickinessMode {
    return StickinessMode.STRICT;
  }

  public async signAft(options: SignAftOptions): Promise<string> {
    const payload = this.createPayload(options, this.algorithm);
    const key = await this.resolveKey();

    const claimsPayload: Record<string, unknown> = {
      sid: payload.claims.sid,
    };

    if (
      typeof payload.claims.scp === "string" &&
      payload.claims.scp.length > 0
    ) {
      claimsPayload.scp = payload.claims.scp;
    }

    if (
      typeof payload.claims.client_sid === "string" &&
      payload.claims.client_sid.length > 0
    ) {
      claimsPayload.client_sid = payload.claims.client_sid;
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = payload.claims.exp;

    try {
      const token = await new SignJWT(claimsPayload)
        .setProtectedHeader({ alg: this.algorithm, kid: this.kid })
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(key);

      return token;
    } catch (error) {
      logger.error("aft_signing_failed", {
        kid: this.kid,
        algorithm: this.algorithm,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error instanceof Error ? error : new Error(String(error));
    }
  }

  private async resolveKey(): Promise<CryptoKey> {
    if (!this.cryptoKeyPromise) {
      this.cryptoKeyPromise = importPKCS8(
        this.privateKeyPem,
        this.algorithm,
      ).catch((error) => {
        this.cryptoKeyPromise = null;
        logger.error("aft_private_key_import_failed", {
          kid: this.kid,
          algorithm: this.algorithm,
          error: error instanceof Error ? error.message : String(error),
        });
        throw error instanceof Error ? error : new Error(String(error));
      });
    }

    return this.cryptoKeyPromise;
  }
}

export interface CreateAftSignerOptions {
  securityLevel: StickinessMode;
  kid: string;
  privateKeyPem?: string | null;
  algorithm?: string;
  maxTtlSec?: number;
}

export function createAftSigner(options: CreateAftSignerOptions): AFTSigner {
  const {
    securityLevel,
    kid,
    privateKeyPem = null,
    algorithm = "EdDSA",
    maxTtlSec = 7200,
  } = options;

  switch (securityLevel) {
    case StickinessMode.STRICT: {
      if (!privateKeyPem) {
        throw new Error("Private key PEM required for strict security level");
      }
      return new SignedAFTSigner({ kid, privateKeyPem, algorithm, maxTtlSec });
    }
    case StickinessMode.SIGNED_OPTIONAL: {
      if (privateKeyPem) {
        return new SignedAFTSigner({
          kid,
          privateKeyPem,
          algorithm,
          maxTtlSec,
        });
      }
      return new UnsignedAFTSigner(kid, maxTtlSec);
    }
    case StickinessMode.SID_ONLY:
      return new NoAFTSigner();
    default:
      throw new Error(`Unknown security level: ${securityLevel}`);
  }
}
