import { AsnConvert } from "@peculiar/asn1-schema";
import {
  Certificate,
  GeneralSubtree,
  Name,
  NameConstraints,
  SubjectAlternativeName,
  id_ce_nameConstraints,
  id_ce_subjectAltName,
  Extension,
} from "@peculiar/asn1-x509";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha2.js";
import { etc as edEtc, verify as ed25519Verify } from "@noble/ed25519";
import { getLogger } from "@naylence/runtime";

const logger = getLogger("naylence.fame.security.cert.util");

const CACHE_LIMIT = 512;
const OID_ED25519 = "1.3.101.112";
const textEncoder = new TextEncoder();

interface ParsedCertificate {
  raw: Uint8Array;
  certificate: Certificate;
  serialNumber: string;
  subjectName: string;
  issuerName: string;
  subjectPublicKey: Uint8Array;
}

interface CacheEntry {
  value: Uint8Array;
  expiresAt: number;
}

const trustCache = new Map<string, CacheEntry>();

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

export interface PublicKeyFromX5cOptions {
  trustStorePem?: string | null;
  enforceNameConstraints?: boolean;
  returnCertificate?: boolean;
}

export function publicKeyFromX5c(
  x5c: string[],
  options?: PublicKeyFromX5cOptions,
): Uint8Array;
export function publicKeyFromX5c(
  x5c: string[],
  options: PublicKeyFromX5cOptions & { returnCertificate: true },
): { publicKey: Uint8Array; certificate: Certificate };
export function publicKeyFromX5c(
  x5c: string[],
  options: PublicKeyFromX5cOptions = {},
): Uint8Array | { publicKey: Uint8Array; certificate: Certificate } {
  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new Error("Empty certificate chain");
  }

  const callId = generateCallId();
  const enforceNameConstraints = options.enforceNameConstraints ?? true;
  const trustStorePem = normalizeTrustStoreOption(
    options.trustStorePem ?? null,
  );
  const returnCertificate = options.returnCertificate ?? false;

  const { parsed, chainBytes } = parseCertificateChain(x5c);

  logger.debug("public_key_from_x5c_called", {
    call_id: callId,
    x5c_count: parsed.length,
    enforce_name_constraints: enforceNameConstraints,
    has_trust_store: Boolean(trustStorePem),
    return_cert: returnCertificate,
  });

  let cacheKey: string | null = null;
  if (!returnCertificate) {
    cacheKey = buildCacheKey(chainBytes, trustStorePem, enforceNameConstraints);
    const cached = getCachedPublicKey(cacheKey);
    if (cached) {
      logger.debug("certificate_cache_hit", {
        call_id: callId,
        cache_key: cacheKey,
      });
      return cached;
    }
    logger.debug("certificate_cache_miss", {
      call_id: callId,
      cache_key: cacheKey,
    });
  }

  const validation = validateCertificateChain(
    parsed,
    enforceNameConstraints,
    trustStorePem,
  );

  if (cacheKey) {
    setCachedPublicKey(cacheKey, validation.publicKey, validation.notAfter);
  }

  if (returnCertificate) {
    return {
      publicKey: validation.publicKey.slice(),
      certificate: validation.certificate,
    };
  }

  return validation.publicKey.slice();
}

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

  try {
    publicKeyFromX5c(x5c as string[], {
      trustStorePem,
      enforceNameConstraints,
    });
    return { isValid: true };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : String(error ?? "unknown");
    const normalized = `Certificate validation failed: ${message}`;
    if (strict) {
      throw new Error(normalized);
    }
    return { isValid: false, error: normalized };
  }
}

function validateCertificateChain(
  parsed: ParsedCertificate[],
  enforceNameConstraints: boolean,
  trustStorePem: string | null,
): {
  publicKey: Uint8Array;
  certificate: Certificate;
  notAfter: Date;
} {
  const leaf = parsed[0]!;
  const nowMs = Date.now();
  const notBefore =
    leaf.certificate.tbsCertificate.validity.notBefore.getTime();
  const notAfter = leaf.certificate.tbsCertificate.validity.notAfter.getTime();
  const notBeforeMs = notBefore.getTime();
  const notAfterMs = notAfter.getTime();

  if (nowMs < notBeforeMs || nowMs > notAfterMs) {
    throw new Error(
      `Certificate is not currently valid (notBefore: ${notBefore.toISOString()}, notAfter: ${notAfter.toISOString()}, now: ${new Date(nowMs).toISOString()})`,
    );
  }

  const issuers = parsed.slice(1);
  if (enforceNameConstraints && issuers.length > 0) {
    const leafUris = extractUrisFromCert(leaf.certificate);
    validateNameConstraints(issuers, leafUris);
  }

  if (trustStorePem) {
    validateTrustAnchor(parsed, trustStorePem);
  }

  validateChainContinuity(parsed);

  const publicKey = leaf.subjectPublicKey.slice();
  return {
    publicKey,
    certificate: leaf.certificate,
    notAfter,
  };
}

function parseCertificateChain(x5c: string[]): {
  parsed: ParsedCertificate[];
  chainBytes: Uint8Array;
} {
  const parsed: ParsedCertificate[] = [];
  const derChunks: Uint8Array[] = [];

  for (let index = 0; index < x5c.length; index += 1) {
    const entry = x5c[index];
    if (typeof entry !== "string" || entry.trim().length === 0) {
      throw new Error(`Invalid certificate at index ${index}`);
    }

    let der: Uint8Array;
    try {
      der = decodeBase64(entry);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed to decode certificate at index ${index}: ${reason}`,
      );
    }

    let certificate: Certificate;
    try {
      certificate = AsnConvert.parse(der, Certificate);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Failed to parse certificate at index ${index}: ${reason}`,
      );
    }

    parsed.push(createParsedCertificate(certificate, der));
    derChunks.push(der);
  }

  return { parsed, chainBytes: concatBytes(derChunks) };
}

function createParsedCertificate(
  certificate: Certificate,
  raw: Uint8Array,
): ParsedCertificate {
  return {
    raw,
    certificate,
    serialNumber: toHex(
      new Uint8Array(certificate.tbsCertificate.serialNumber),
    ).toUpperCase(),
    subjectName: serializeName(certificate.tbsCertificate.subject),
    issuerName: serializeName(certificate.tbsCertificate.issuer),
    subjectPublicKey: new Uint8Array(
      certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
    ).slice(),
  };
}

function extractUrisFromCert(cert: Certificate): string[] {
  const extension = findExtension(cert, id_ce_subjectAltName);
  if (!extension) {
    return [];
  }

  const subjectAlternativeName = AsnConvert.parse(
    extension.extnValue.buffer,
    SubjectAlternativeName,
  );

  const uris: string[] = [];
  for (const generalName of subjectAlternativeName) {
    if (generalName.uniformResourceIdentifier) {
      uris.push(generalName.uniformResourceIdentifier);
    }
  }
  return uris;
}

function validateNameConstraints(
  issuers: ParsedCertificate[],
  leafUris: string[],
): void {
  for (const issuer of issuers) {
    const extension = findExtension(issuer.certificate, id_ce_nameConstraints);
    if (!extension) {
      continue;
    }

    const constraints = AsnConvert.parse(
      extension.extnValue.buffer,
      NameConstraints,
    );
    if (!constraints.permittedSubtrees) {
      continue;
    }

    const permittedUris = collectPermittedUris(
      Array.from(constraints.permittedSubtrees),
    );
    if (permittedUris.length === 0) {
      continue;
    }

    for (const uri of leafUris) {
      const allowed = permittedUris.some((prefix) => uri.startsWith(prefix));
      if (!allowed) {
        throw new Error(
          `URI '${uri}' violates name constraints - not in permitted subtrees: ${permittedUris.join(", ")}`,
        );
      }
    }
  }
}

function collectPermittedUris(subtrees: Iterable<GeneralSubtree>): string[] {
  const uris: string[] = [];
  for (const subtree of subtrees) {
    if (
      subtree.base.uniformResourceIdentifier &&
      subtree.base.uniformResourceIdentifier.length > 0
    ) {
      uris.push(subtree.base.uniformResourceIdentifier);
    }
  }
  return uris;
}

function validateTrustAnchor(
  chain: ParsedCertificate[],
  trustStorePem: string,
): void {
  const trustedCerts = parseTrustStore(trustStorePem);
  if (trustedCerts.length === 0) {
    throw new Error("No valid certificates found in trust store");
  }

  logger.debug("trust_anchor_validation_start", {
    chain_length: chain.length,
    trust_store_cert_count: trustedCerts.length,
  });

  const chainInfo = chain.map(
    (cert, index) =>
      `[${index}] ${cert.subjectName} (Serial: ${cert.serialNumber})`,
  );
  const trustedInfo = trustedCerts.map(
    (cert, index) =>
      `[${index}] ${cert.subjectName} (Serial: ${cert.serialNumber})`,
  );

  logger.debug("certificate_chain_validation", {
    chain_certificates: chainInfo,
    trust_store_certificates: trustedInfo,
  });

  // Strategy 1: direct trust (exact certificate match)
  for (let i = 0; i < chain.length; i += 1) {
    const cert = chain[i]!;
    const match = trustedCerts.find(
      (trusted) =>
        trusted.serialNumber === cert.serialNumber &&
        namesEqual(
          trusted.certificate.tbsCertificate.subject,
          cert.certificate.tbsCertificate.subject,
        ),
    );
    if (match) {
      logger.debug("certificate_chain_trust_validation_passed", {
        matching_serial: match.serialNumber,
        validation_strategy: `direct_trust_cert_${i}`,
      });
      return;
    }
  }

  const leaf = chain[0]!;

  // Strategy 2: leaf issuer in trust store
  for (const trusted of trustedCerts) {
    if (
      namesEqual(
        trusted.certificate.tbsCertificate.subject,
        leaf.certificate.tbsCertificate.issuer,
      ) &&
      trusted.serialNumber !== leaf.serialNumber
    ) {
      verifyCertificateSignature(leaf.certificate, trusted.certificate);
      logger.debug("certificate_chain_trust_validation_passed", {
        matching_serial: trusted.serialNumber,
        validation_strategy: "leaf_issuer_trust",
      });
      return;
    }
  }

  // Strategy 3: any intermediate issuer in trust store
  for (let index = 1; index < chain.length; index += 1) {
    const intermediate = chain[index]!;
    for (const trusted of trustedCerts) {
      if (
        namesEqual(
          trusted.certificate.tbsCertificate.subject,
          intermediate.certificate.tbsCertificate.issuer,
        ) &&
        trusted.serialNumber !== intermediate.serialNumber
      ) {
        verifyCertificateSignature(
          intermediate.certificate,
          trusted.certificate,
        );
        logger.debug("certificate_chain_trust_validation_passed", {
          matching_serial: trusted.serialNumber,
          validation_strategy: `intermediate_issuer_trust_cert_${index}`,
        });
        return;
      }
    }
  }

  logger.warning("certificate_chain_trust_validation_failed", {
    leaf_subject: leaf.subjectName,
    leaf_issuer: leaf.issuerName,
    leaf_serial: leaf.serialNumber,
    trusted_certificates: trustedInfo,
    chain_certificates: chainInfo,
    reason: "no_matching_trust_anchor",
  });

  throw new Error("Certificate chain is not rooted in a trusted anchor");
}

function parseTrustStore(trustStorePem: string): ParsedCertificate[] {
  const normalized = normalizePem(trustStorePem);
  const blocks = extractPemBlocks(normalized);
  const parsed: ParsedCertificate[] = [];

  for (const block of blocks) {
    try {
      const der = decodeBase64(block);
      const certificate = AsnConvert.parse(der, Certificate);
      parsed.push(createParsedCertificate(certificate, der));
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      logger.debug("trust_store_certificate_parse_failed", { reason });
    }
  }

  return parsed;
}

function extractPemBlocks(pem: string): string[] {
  const blocks: string[] = [];
  const regex =
    /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/gu;
  let match: RegExpExecArray | null;

  // eslint-disable-next-line no-cond-assign
  while ((match = regex.exec(pem)) !== null) {
    const body = match[1] ?? "";
    blocks.push(body.replace(/\s+/gu, ""));
  }

  return blocks;
}

function validateChainContinuity(chain: ParsedCertificate[]): void {
  if (chain.length <= 1) {
    return;
  }

  logger.debug("validating_chain_continuity", { chain_length: chain.length });

  for (let index = 0; index < chain.length - 1; index += 1) {
    const cert = chain[index]!;
    const issuer = chain[index + 1]!;

    if (
      !namesEqual(
        cert.certificate.tbsCertificate.issuer,
        issuer.certificate.tbsCertificate.subject,
      )
    ) {
      logger.warning("certificate_chain_continuity_failed", {
        cert_index: index,
        cert_subject: cert.subjectName,
        cert_issuer: cert.issuerName,
        expected_issuer_subject: issuer.subjectName,
        reason: "issuer_name_mismatch",
      });
      throw new Error(
        `Certificate chain continuity broken: certificate at index ${index} issuer does not match next certificate subject`,
      );
    }

    try {
      verifyCertificateSignature(cert.certificate, issuer.certificate);
      logger.debug("chain_continuity_verification_success", {
        cert_index: index,
        cert_serial: cert.serialNumber,
        issuer_serial: issuer.serialNumber,
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      logger.warning("certificate_chain_continuity_failed", {
        cert_index: index,
        cert_subject: cert.subjectName,
        issuer_subject: issuer.subjectName,
        cert_serial: cert.serialNumber,
        issuer_serial: issuer.serialNumber,
        error: reason,
        reason: "signature_verification_failed",
      });
      throw new Error(
        `Certificate chain continuity broken: certificate at index ${index} was not signed by certificate at index ${index + 1}: ${reason}`,
      );
    }
  }

  logger.debug("chain_continuity_validation_passed", {
    chain_length: chain.length,
  });
}

function verifyCertificateSignature(
  certificate: Certificate,
  issuer: Certificate,
): void {
  ensureEd25519Support();

  const signatureAlgorithm = certificate.signatureAlgorithm.algorithm;
  const issuerAlgorithm =
    issuer.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm;

  if (signatureAlgorithm !== OID_ED25519 || issuerAlgorithm !== OID_ED25519) {
    throw new Error(
      `Unsupported signature algorithm (certificate: ${signatureAlgorithm}, issuer: ${issuerAlgorithm})`,
    );
  }

  const signatureBytes = new Uint8Array(certificate.signatureValue);
  const tbsBytes = new Uint8Array(
    AsnConvert.serialize(certificate.tbsCertificate),
  );
  const issuerKey = new Uint8Array(
    issuer.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey,
  );

  if (issuerKey.length !== 32) {
    throw new Error("Issuer Ed25519 public key must be 32 bytes");
  }

  const valid = ed25519Verify(signatureBytes, tbsBytes, issuerKey);
  if (!valid) {
    throw new Error("Certificate signature verification failed");
  }
}

function ensureEd25519Support(): void {
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

function findExtension(
  certificate: Certificate,
  oid: string,
): Extension | null {
  const extensions = certificate.tbsCertificate.extensions;
  if (!extensions) {
    return null;
  }

  for (const extension of extensions) {
    if (extension.extnID === oid) {
      return extension;
    }
  }

  return null;
}

function namesEqual(a: Name, b: Name): boolean {
  const left = new Uint8Array(AsnConvert.serialize(a));
  const right = new Uint8Array(AsnConvert.serialize(b));

  if (left.length !== right.length) {
    return false;
  }

  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }

  return true;
}

function serializeName(name: Name): string {
  const rdns = Array.from(name);
  return rdns
    .map((rdn) =>
      Array.from(rdn)
        .map((attr) => `${oidToLabel(attr.type)}=${attr.value.toString()}`)
        .join("+"),
    )
    .join(",");
}

function oidToLabel(oid: string): string {
  switch (oid) {
    case "2.5.4.3":
      return "CN";
    case "2.5.4.6":
      return "C";
    case "2.5.4.7":
      return "L";
    case "2.5.4.8":
      return "ST";
    case "2.5.4.10":
      return "O";
    case "2.5.4.11":
      return "OU";
    default:
      return oid;
  }
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

function decodeBase64(input: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    const normalized = input.replace(/\s+/gu, "");
    return new Uint8Array(Buffer.from(normalized, "base64"));
  }

  if (typeof atob === "function") {
    const normalized = input.replace(/\s+/gu, "");
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  throw new Error("No base64 decoder available in this environment");
}

function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function buildCacheKey(
  chainBytes: Uint8Array,
  trustStorePem: string | null,
  enforceNameConstraints: boolean,
): string {
  const chainHash = toHex(sha256(chainBytes));
  const trustHash = trustStorePem
    ? toHex(sha256(textEncoder.encode(trustStorePem)))
    : "no-trust";
  const constraintFlag = enforceNameConstraints ? "nc1" : "nc0";
  return `${chainHash}|${trustHash}|${constraintFlag}`;
}

function getCachedPublicKey(cacheKey: string): Uint8Array | null {
  const entry = trustCache.get(cacheKey);
  if (!entry) {
    return null;
  }

  if (Date.now() > entry.expiresAt) {
    trustCache.delete(cacheKey);
    logger.debug("certificate_cache_expired", { cache_key: cacheKey });
    return null;
  }

  return entry.value.slice();
}

function setCachedPublicKey(
  cacheKey: string,
  value: Uint8Array,
  notAfter: Date,
): void {
  while (trustCache.size >= CACHE_LIMIT) {
    const firstKey = trustCache.keys().next().value;
    if (firstKey === undefined) {
      break;
    }
    trustCache.delete(firstKey);
    logger.debug("certificate_cache_evicted", { cache_key: firstKey });
  }

  trustCache.set(cacheKey, {
    value: value.slice(),
    expiresAt: notAfter.getTime(),
  });

  logger.debug("certificate_cache_stored", {
    cache_key: cacheKey,
    expires_at: notAfter.toISOString(),
    cache_size: trustCache.size,
  });
}

function normalizeTrustStoreOption(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return null;
  }

  if (!trimmed.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(
      "trustStorePem must contain PEM-encoded certificates when provided",
    );
  }

  return normalizePem(trimmed);
}

function normalizePem(pem: string): string {
  return pem.replace(/\r/gu, "").trim();
}

function generateCallId(): string {
  return Math.random().toString(36).slice(2, 10);
}
