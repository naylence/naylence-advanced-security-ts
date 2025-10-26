import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate } from "@peculiar/asn1-x509";
import { getLogger } from "@naylence/runtime";

const logger = getLogger("naylence.fame.security.cert.util");

export interface ValidateJwkX5cCertificateOptions {
  jwk: Record<string, unknown>;
  trustStorePem?: string | null;
  enforceNameConstraints?: boolean;
  strict?: boolean;
}

export interface ValidateJwkX5cCertificateResult {
  isValid: boolean;
  error?: string;
}

/**
 * Temporary TypeScript port of validate_jwk_x5c_certificate.
 *
 * NOTE: The full certificate chain validation logic from the Python runtime
 * is still being ported. This implementation performs lightweight structure
 * checks and defers deep X.509 validation until the remaining modules are
 * available.
 */
export function validateJwkX5cCertificate(
  options: ValidateJwkX5cCertificateOptions,
): ValidateJwkX5cCertificateResult {
  const {
    jwk,
    trustStorePem = null,
    enforceNameConstraints = true,
    strict = true,
  } = options;

  if (!jwk || typeof jwk !== "object") {
    const error = "Invalid JWK object";
    if (strict) {
      throw new Error(error);
    }
    return { isValid: false, error };
  }

  const x5c = (jwk as { x5c?: unknown }).x5c;
  if (x5c === undefined) {
    return { isValid: true };
  }

  if (
    !Array.isArray(x5c) ||
    x5c.length === 0 ||
    x5c.some((entry) => typeof entry !== "string")
  ) {
    const error = "Invalid x5c field in JWK";
    if (strict) {
      throw new Error(error);
    }
    return { isValid: false, error };
  }

  // Until full validation is available we only log that certificate validation
  // was requested. This preserves the call sites and allows adding the full
  // chain validation later without changing behaviour.
  logger.debug("validate_jwk_x5c_certificate_placeholder", {
    enforce_name_constraints: enforceNameConstraints,
    has_trust_store: Boolean(trustStorePem),
    chain_length: x5c.length,
  });

  return { isValid: true };
}

/**
 * Extract public key from X.509 certificate chain.
 *
 * Parses the leaf certificate from an x5c array and extracts the raw public key bytes.
 * For Ed25519 certificates, this returns the 32-byte public key.
 *
 * @param x5c - Array of base64-encoded DER certificates (leaf first)
 * @param options - Validation options
 * @returns The raw public key bytes from the leaf certificate
 * @throws Error if certificate parsing or validation fails
 */
export function publicKeyFromX5c(
  x5c: string[],
  options: {
    enforceNameConstraints?: boolean;
    trustStorePem?: string;
  } = {},
): Uint8Array {
  if (!x5c || x5c.length === 0) {
    throw new Error("Empty certificate chain");
  }

  // Decode leaf certificate
  const certB64 = x5c[0];
  if (typeof certB64 !== "string") {
    throw new Error("Invalid certificate in x5c array - must be base64 string");
  }

  let derBytes: Buffer;
  try {
    derBytes = Buffer.from(certB64, "base64");
  } catch (error) {
    throw new Error(
      `Failed to decode base64 certificate: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Parse DER-encoded certificate
  let cert: Certificate;
  try {
    cert = AsnConvert.parse(derBytes, Certificate);
  } catch (error) {
    throw new Error(
      `Failed to parse X.509 certificate: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  // Basic temporal validity check
  const now = Date.now(); // milliseconds since epoch
  const notBefore = cert.tbsCertificate.validity.notBefore;
  const notAfter = cert.tbsCertificate.validity.notAfter;

  // Time from ASN.1 has getTime() method returning Date object
  const notBeforeDate = notBefore.getTime();
  const notAfterDate = notAfter.getTime();
  const notBeforeMs =
    notBeforeDate instanceof Date
      ? notBeforeDate.getTime()
      : Number(notBeforeDate);
  const notAfterMs =
    notAfterDate instanceof Date
      ? notAfterDate.getTime()
      : Number(notAfterDate);

  if (now < notBeforeMs || now > notAfterMs) {
    throw new Error(
      `Certificate is not currently valid (notBefore: ${new Date(notBeforeMs).toISOString()}, notAfter: ${new Date(notAfterMs).toISOString()}, now: ${new Date(now).toISOString()})`,
    );
  }

  // TODO: Implement name constraints validation when enforceNameConstraints is true
  if (options.enforceNameConstraints) {
    logger.debug("name_constraints_validation_not_implemented", {
      enforcement_requested: true,
    });
  }

  // TODO: Implement trust store validation when trustStorePem is provided
  if (options.trustStorePem) {
    logger.debug("trust_store_validation_not_implemented", {
      has_trust_store: true,
    });
  }

  // Extract public key from leaf certificate
  const publicKeyInfo = cert.tbsCertificate.subjectPublicKeyInfo;

  // For Ed25519, the subjectPublicKey is a BIT STRING containing the raw 32-byte public key
  // The BIT STRING is stored as an ArrayBuffer
  const publicKeyBitString = publicKeyInfo.subjectPublicKey;

  // Convert ArrayBuffer to Uint8Array
  return new Uint8Array(publicKeyBitString);
}
