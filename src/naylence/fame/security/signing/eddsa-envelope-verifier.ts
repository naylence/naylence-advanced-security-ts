import { etc as edEtc, verify } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import type { DataFrame, FameEnvelope } from "@naylence/core";
import { SigningMaterial } from "@naylence/core";
import {
  SigningConfigClass,
  secureDigest,
  type KeyProvider,
} from "@naylence/runtime";
import {
  canonicalJson,
  decodeBase64Url,
  frameDigest,
  immutableHeaders,
} from "naylence-runtime/naylence/fame/security/signing/eddsa-signer-verifier.js";
import { encodeUtf8 } from "naylence-runtime/naylence/fame/security/signing/eddsa-utils.js";
import { JWKValidationError, validateSigningKey } from "@naylence/runtime";
import { publicKeyFromX5c } from "../cert/util.js";

type SigningConfig = InstanceType<typeof SigningConfigClass>;

interface VerifierJwk extends Record<string, unknown> {
  kid?: string;
  sid?: string;
  x?: string;
  crv_x?: string;
  pub?: string;
  x5c?: unknown;
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value;
}

function isDataFrame(frame: FameEnvelope["frame"]): frame is DataFrame {
  return (frame as { type?: string }).type === "Data";
}

function encodeBase64Url(value: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value)
      .toString("base64")
      .replace(/\+/gu, "-")
      .replace(/\//gu, "_")
      .replace(/=+$/u, "");
  }

  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }

  if (typeof btoa === "function") {
    return btoa(binary)
      .replace(/\+/gu, "-")
      .replace(/\//gu, "_")
      .replace(/=+$/u, "");
  }

  throw new Error("No base64 encoder available in this environment");
}

function ensureNobleSha512Fallback(): void {
  const etcPatch = edEtc as typeof edEtc & {
    sha512?: (message: Uint8Array) => Uint8Array;
    sha512Sync?: (...messages: Uint8Array[]) => Uint8Array;
  };

  if (!etcPatch.sha512) {
    etcPatch.sha512 = (message: Uint8Array) => sha512(message);
  }

  if (!etcPatch.sha512Sync) {
    etcPatch.sha512Sync = (...messages: Uint8Array[]): Uint8Array => {
      if (messages.length === 1) {
        return sha512(messages[0]!);
      }

      const combined = edEtc.concatBytes(...messages);
      return sha512(combined);
    };
  }
}

function normalizeCertificateKey(
  jwk: VerifierJwk,
  signingConfig: SigningConfig,
): string | null {
  if (!Array.isArray(jwk.x5c) || jwk.x5c.length === 0) {
    return null;
  }

  if (signingConfig.signingMaterial !== SigningMaterial.X509_CHAIN) {
    throw new Error("Certificate keys are disabled by signing policy");
  }

  const trustStorePem = process.env.FAME_CA_CERTS;
  if (!trustStorePem) {
    throw new Error(
      "FAME_CA_CERTS environment variable must be set to a PEM file containing trusted CA certs when using certificate-based verification",
    );
  }

  const publicKey = publicKeyFromX5c(jwk.x5c as string[], {
    enforceNameConstraints: signingConfig.validateCertNameConstraints,
    trustStorePem,
  });

  if (publicKey.length !== 32) {
    throw new Error("Certificate public key must be 32 bytes for Ed25519");
  }

  return encodeBase64Url(publicKey);
}

async function loadPublicKey(
  jwk: VerifierJwk,
  signingConfig: SigningConfig,
): Promise<Uint8Array> {
  const certificateKey = normalizeCertificateKey(jwk, signingConfig);

  const candidate =
    certificateKey ??
    (typeof jwk.x === "string"
      ? jwk.x
      : typeof jwk.crv_x === "string"
        ? jwk.crv_x
        : jwk.pub);

  if (typeof candidate !== "string") {
    throw new Error("JWK missing public key material");
  }

  return decodeBase64Url(candidate);
}

export interface EdDSAEnvelopeVerifierOptions {
  readonly signingConfig?: SigningConfig | null;
}

export class EdDSAEnvelopeVerifier {
  private readonly keyProvider: KeyProvider;

  private readonly signingConfig: SigningConfig;

  public constructor(
    keyProvider: KeyProvider,
    options: EdDSAEnvelopeVerifierOptions = {},
  ) {
    this.keyProvider = keyProvider;
    this.signingConfig = options.signingConfig ?? new SigningConfigClass();
    ensureNobleSha512Fallback();
  }

  public async verifyEnvelope(
    envelope: FameEnvelope,
    options: { checkPayload?: boolean; logical?: string } = {},
  ): Promise<boolean> {
    const signatureHeader = envelope.sec?.sig;
    if (!signatureHeader) {
      throw new Error("Missing envelope.sec.sig header");
    }

    const kid = assertString(
      signatureHeader.kid,
      "Signature header missing 'kid'",
    );
    const signatureValue = assertString(
      signatureHeader.val,
      "Signature header missing 'val'",
    );

    const jwk = (await this.keyProvider.getKey(kid)) as VerifierJwk | null;
    if (!jwk) {
      throw new Error(`Unknown key id: ${kid}`);
    }

    try {
      validateSigningKey(jwk);
    } catch (error) {
      if (error instanceof JWKValidationError) {
        throw new Error(
          `Key ${kid} is not valid for signing: ${error.message}`,
        );
      }
      throw error;
    }

    const checkPayload = options.checkPayload ?? true;

    let trustedDigest: string;
    if (isDataFrame(envelope.frame)) {
      if (checkPayload) {
        if (!envelope.frame.pd) {
          throw new Error("DataFrame missing payload digest (pd field)");
        }
        const payload = envelope.frame.payload ?? "";
        const payloadString = payload === "" ? "" : canonicalJson(payload);
        const actualDigest = secureDigest(payloadString);
        if (actualDigest !== envelope.frame.pd) {
          throw new Error("Payload digest mismatch in DataFrame");
        }
        trustedDigest = actualDigest;
      } else {
        if (!envelope.frame.pd) {
          throw new Error(
            "DataFrame missing payload digest (pd field) for intermediate verification",
          );
        }
        trustedDigest = envelope.frame.pd;
      }
    } else {
      trustedDigest = frameDigest(envelope.frame);
    }

    const sid = assertString(jwk.sid, "Signing key missing sid");
    const immutable = canonicalJson(immutableHeaders(envelope));
    const tbs = new Uint8Array(
      encodeUtf8(sid).length +
        1 +
        encodeUtf8(immutable).length +
        1 +
        encodeUtf8(trustedDigest).length,
    );

    const sidBytes = encodeUtf8(sid);
    const immBytes = encodeUtf8(immutable);
    const digestBytes = encodeUtf8(trustedDigest);
    let offset = 0;

    tbs.set(sidBytes, offset);
    offset += sidBytes.length;
    tbs[offset] = 0x1f;
    offset += 1;

    tbs.set(immBytes, offset);
    offset += immBytes.length;
    tbs[offset] = 0x1f;
    offset += 1;

    tbs.set(digestBytes, offset);

    const signatureBytes = decodeBase64Url(signatureValue);
    if (signatureBytes.length !== 64) {
      throw new Error("Signature must be 64 bytes for Ed25519");
    }

    const publicKey = await loadPublicKey(jwk, this.signingConfig);
    if (publicKey.length !== 32) {
      throw new Error("Ed25519 public key must be 32 bytes");
    }

    const valid = await verify(signatureBytes, tbs, publicKey);
    if (!valid) {
      throw new Error("Envelope signature verification failed");
    }

    return true;
  }
}

export type { SigningConfig as SigningConfigInstance };
