import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  Attributes,
  CertificationRequest,
  CertificationRequestInfo,
} from "@peculiar/asn1-csr";
import {
  AlgorithmIdentifier,
  Attribute,
  AttributeTypeAndValue,
  AttributeValue,
  Extension,
  Extensions,
  GeneralName,
  Name,
  RelativeDistinguishedName,
  SubjectAlternativeName,
  SubjectPublicKeyInfo,
  id_ce_subjectAltName,
} from "@peculiar/asn1-x509";

import { CreatedEd25519Csr } from "./csr-types.js";

const ED25519_OID = "1.3.101.112";
const OID_COMMON_NAME = "2.5.4.3";
const EXTENSION_REQUEST_OID = "1.2.840.113549.1.9.14";
const LOGICAL_URI_PREFIX = "naylence://";
const CSR_PEM_TAG = "CERTIFICATE REQUEST";

export interface CreateEd25519CsrFromPemOptions {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly commonName: string;
  readonly logicals?: readonly string[];
}

export async function createEd25519CsrFromPem(
  options: CreateEd25519CsrFromPemOptions,
): Promise<CreatedEd25519Csr> {
  const { privateKeyPem, publicKeyPem, commonName } = options;
  const sanitizedLogicals = sanitizeLogicals(options.logicals);

  const crypto = await ensureWebCrypto();
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(privateKeyPem),
    { name: "Ed25519" },
    false,
    ["sign"],
  );

  const publicKeyDer = pemToArrayBuffer(publicKeyPem);
  const subjectPublicKeyInfo = AsnConvert.parse(
    publicKeyDer,
    SubjectPublicKeyInfo,
  );

  const subject = buildSubjectName(commonName);
  const attributes = buildAttributes(sanitizedLogicals);

  const requestInfo = new CertificationRequestInfo({
    subject,
    subjectPKInfo: subjectPublicKeyInfo,
    attributes,
  });

  const requestInfoDer = AsnConvert.serialize(requestInfo);
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    requestInfoDer,
  );

  const certificationRequest = new CertificationRequest({
    certificationRequestInfo: requestInfo,
    signatureAlgorithm: new AlgorithmIdentifier({
      algorithm: ED25519_OID,
    }),
    signature: encodeBitString(signature),
  });

  const csrDer = AsnConvert.serialize(certificationRequest);
  const csrPem = arrayBufferToPem(csrDer, CSR_PEM_TAG);

  return { csrDer, csrPem };
}

function sanitizeLogicals(logicals?: readonly string[]): string[] {
  if (!Array.isArray(logicals)) {
    return [];
  }
  const seen = new Set<string>();
  const result: string[] = [];
  for (const entry of logicals) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (!trimmed || seen.has(trimmed)) {
      continue;
    }
    seen.add(trimmed);
    result.push(trimmed);
  }
  return result;
}

function buildAttributes(logicals: string[]): Attributes {
  const attributes = new Attributes();
  if (logicals.length === 0) {
    return attributes;
  }

  const san = new SubjectAlternativeName(
    logicals.map(
      (logical) =>
        new GeneralName({
          uniformResourceIdentifier: `${LOGICAL_URI_PREFIX}${logical}`,
        }),
    ),
  );

  const extensions = new Extensions([
    new Extension({
      extnID: id_ce_subjectAltName,
      critical: false,
      extnValue: new OctetString(AsnConvert.serialize(san)),
    }),
  ]);

  attributes.push(
    new Attribute({
      type: EXTENSION_REQUEST_OID,
      values: [AsnConvert.serialize(extensions)],
    }),
  );

  return attributes;
}

function buildSubjectName(commonName: string): Name {
  const trimmed = commonName.trim();
  if (trimmed.length === 0) {
    throw new Error("commonName must be a non-empty string");
  }

  return new Name([
    new RelativeDistinguishedName([
      new AttributeTypeAndValue({
        type: OID_COMMON_NAME,
        value: new AttributeValue({ utf8String: trimmed }),
      }),
    ]),
  ]);
}

async function ensureWebCrypto(): Promise<Crypto> {
  if (globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }

  if (typeof process !== "undefined" && process?.versions?.node) {
    const module = await import("node:crypto");
    const webcrypto = (module as { webcrypto?: Crypto }).webcrypto;
    if (!webcrypto?.subtle) {
      throw new Error("WebCrypto API is not available in this Node.js runtime");
    }
    (globalThis as { crypto?: Crypto }).crypto = webcrypto as unknown as Crypto;
    return webcrypto as unknown as Crypto;
  }

  throw new Error("WebCrypto API is not available in this environment");
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const normalized = pem
    .replace(/-----BEGIN[^-]+-----/g, "")
    .replace(/-----END[^-]+-----/g, "")
    .replace(/\s+/g, "");
  const bytes = base64ToBytes(normalized);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}

function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(base64, "base64"));
  }

  if (typeof globalThis.atob === "function") {
    const binary = globalThis.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  throw new Error("Base64 decoding not available in this environment");
}

function arrayBufferToPem(buffer: ArrayBuffer, tag: string): string {
  const base64 = bytesToBase64(new Uint8Array(buffer));
  const lines: string[] = [];
  for (let index = 0; index < base64.length; index += 64) {
    lines.push(base64.slice(index, index + 64));
  }
  return `-----BEGIN ${tag}-----\n${lines.join("\n")}\n-----END ${tag}-----\n`;
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }

  if (typeof globalThis.btoa === "function") {
    let binary = "";
    for (let index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]!);
    }
    return globalThis.btoa(binary);
  }

  throw new Error("Base64 encoding not available in this environment");
}

function encodeBitString(signature: ArrayBuffer): ArrayBuffer {
  const signatureBytes = new Uint8Array(signature);
  const result = new Uint8Array(signatureBytes.length + 1);
  result.set(signatureBytes, 1);
  return result.buffer;
}
