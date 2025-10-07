import { getLogger } from "naylence-runtime";

const logger = getLogger("certificate-util");

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
  options: ValidateJwkX5cCertificateOptions
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

  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.some((entry) => typeof entry !== "string")) {
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
