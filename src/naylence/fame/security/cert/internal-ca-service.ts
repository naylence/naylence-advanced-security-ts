/**
 * Certificate Authority signing service for node certificates.
 *
 * Provides in-process API for issuing certificates with node physical
 * and host-like logical address information using SPIFFE-compliant identities.
 */

import type { CertificateIssuanceResponse, CertificateSigningRequest } from "./ca-types.js";
import { CAService } from "./ca-types.js";

// Certificate extension OIDs (using placeholder PEN)
export const SID_OID = "1.3.6.1.4.1.58530.1";
export const LOGICALS_OID = "1.3.6.1.4.1.58530.2";
export const NODE_ID_OID = "1.3.6.1.4.1.58530.4";

/**
 * X.509 module interface (lazy-loaded).
 */
interface X509Module {
  X509Certificate: new (rawData: BufferSource) => {
    readonly subject: string;
    readonly issuer: string;
    readonly serialNumber: string;
    readonly notBefore: Date;
    readonly notAfter: Date;
    readonly publicKey: CryptoKey;
    getExtension(oid: string): ArrayBuffer | null;
  };
  X509CertificateGenerator: new () => {
    serialNumber: string;
    notBefore: Date;
    notAfter: Date;
    extensions: Array<{ type: string; critical: boolean; value: ArrayBuffer }>;
    create(options: {
      publicKey: CryptoKey;
      signingKey: CryptoKey;
      subject: string;
      issuer: string;
    }): Promise<ArrayBuffer>;
  };
  Name: {
    parse(name: string): unknown;
  };
}

let x509ModulePromise: Promise<X509Module | null> | null = null;

/**
 * Lazy-load the @peculiar/x509 module.
 */
async function loadX509Module(): Promise<X509Module | null> {
  if (!x509ModulePromise) {
    x509ModulePromise = import("@peculiar/x509")
      .then((mod) => {
        if (mod && typeof mod.X509Certificate === "function") {
          return mod as unknown as X509Module;
        }
        return null;
      })
      .catch((error) => {
        console.error("Failed to load @peculiar/x509:", error);
        return null;
      });
  }

  return x509ModulePromise;
}

/**
 * Options for CASigningService.
 */
export interface CASigningServiceOptions {
  /** Root CA certificate in PEM format */
  rootCertPem: string;

  /** Root CA private key in PEM format */
  rootKeyPem: string;

  /** Optional intermediate CA certificate in PEM format */
  intermediateCertPem?: string;

  /** Optional intermediate CA private key in PEM format */
  intermediateKeyPem?: string;
}

/**
 * In-process certificate signing service.
 *
 * Issues SPIFFE-compliant node certificates with Fame-specific extensions
 * for physical paths and logical addresses.
 */
export class CASigningService extends CAService {
  // TODO: Use these fields when implementing full certificate signing logic
  // @ts-expect-error - Fields will be used in future implementation
  private readonly rootCertPem: string;
  // @ts-expect-error - Fields will be used in future implementation
  private readonly rootKeyPem: string;

  constructor(options: CASigningServiceOptions) {
    super();

    this.rootCertPem = options.rootCertPem;
    this.rootKeyPem = options.rootKeyPem;

    // TODO: Store intermediate cert/key when implementing signing logic
    if (options.intermediateCertPem && options.intermediateKeyPem) {
      console.log("Intermediate CA certificate provided (not yet used)");
    }
  }

  /**
   * Issue a certificate from a CSR.
   *
   * @param csr - Certificate signing request
   * @returns Certificate issuance response with the signed certificate
   */
  async issueCertificate(csr: CertificateSigningRequest): Promise<CertificateIssuanceResponse> {
    // TODO: Implement full certificate signing with @peculiar/x509
    // For now, throw an error indicating this is not yet implemented
    throw new Error(
      `Certificate issuance not yet fully implemented. CSR for ${csr.requesterId} pending implementation.`
    );
  }

  /**
   * Sign a SPIFFE-compatible node certificate with SID-based identity.
   *
   * @param publicKeyPem - Node's public key in PEM format
   * @param nodeId - Unique identifier for the node
   * @param nodeSid - Node's pre-computed SID (base62-encoded)
   * @param physicalPath - Physical path (for SID verification only)
   * @param logicals - List of host-like logical addresses
   * @param ttlDays - Certificate validity period in days
   * @param spiffeTrustDomain - SPIFFE trust domain
   * @returns PEM-encoded signed certificate
   */
  async signNodeCert(
    publicKeyPem: string,
    nodeId: string,
    nodeSid: string,
    physicalPath: string,
    logicals: string[],
    ttlDays: number = 365,
    spiffeTrustDomain: string = "naylence.fame"
  ): Promise<string> {
    // TODO: Full implementation with @peculiar/x509
    // This is a placeholder that returns the structure
    console.log("Signing node certificate:", {
      nodeId,
      nodeSid,
      physicalPath,
      logicals,
      ttlDays,
      spiffeTrustDomain,
      publicKeyPem: publicKeyPem.substring(0, 50) + "...",
    });

    throw new Error("signNodeCert not yet fully implemented");
  }

  /**
   * Create an intermediate CA certificate.
   *
   * @param publicKeyPem - Intermediate CA's public key in PEM format
   * @param caName - Name for the intermediate CA
   * @param permittedPaths - List of logical prefixes this CA can issue for
   * @param ttlDays - Certificate validity period in days
   * @returns PEM-encoded intermediate CA certificate
   */
  async createIntermediateCA(
    publicKeyPem: string,
    caName: string,
    permittedPaths: string[],
    ttlDays: number = 1825 // 5 years default
  ): Promise<string> {
    // TODO: Full implementation with @peculiar/x509
    console.log("Creating intermediate CA:", {
      caName,
      permittedPaths,
      ttlDays,
      publicKeyPem: publicKeyPem.substring(0, 50) + "...",
    });

    throw new Error("createIntermediateCA not yet fully implemented");
  }
}

/**
 * Create a test root CA for development/testing.
 *
 * Generates an Ed25519 key pair and self-signed root CA certificate.
 *
 * @returns Tuple of [rootCertPem, rootKeyPem]
 */
export async function createTestCA(): Promise<[string, string, string]> {
  // Generate Ed25519 key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "Ed25519",
      namedCurve: "Ed25519",
    } as EcKeyGenParams,
    true,
    ["sign", "verify"]
  );

  // Export private key to PEM
  const privateKeyDer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyBase64 = bufferToBase64(privateKeyDer);
  const rootKeyPem = `-----BEGIN PRIVATE KEY-----\n${formatPem(privateKeyBase64)}\n-----END PRIVATE KEY-----\n`;

  // Export public key to PEM
  const publicKeyDer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyBase64 = bufferToBase64(publicKeyDer);
  const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${formatPem(publicKeyBase64)}\n-----END PUBLIC KEY-----\n`;

  // TODO: Generate self-signed root certificate using @peculiar/x509
  // For now, return a placeholder
  const rootCertPem = `-----BEGIN CERTIFICATE-----
MIIBkTCCATegAwIBAgIUTest...Placeholder...
-----END CERTIFICATE-----`;

  console.log("Created test CA with Ed25519 key pair");
  console.log("Public key PEM:", publicKeyPem);

  return [rootCertPem, rootKeyPem, publicKeyPem];
}

/**
 * Extract SPIFFE ID from certificate SAN.
 *
 * @param certPem - Certificate in PEM format
 * @returns SPIFFE ID string or null if not found
 */
export async function extractSpiffeIdFromCert(certPem: string): Promise<string | null> {
  const x509 = await loadX509Module();
  if (!x509) {
    throw new Error("@peculiar/x509 module not available");
  }

  try {
    const certDer = pemToDer(certPem);
    const cert = new x509.X509Certificate(certDer);

    // TODO: Extract SAN extension and find SPIFFE URI
    // This requires accessing the certificate extensions
    console.log("Extracting SPIFFE ID from cert:", cert.subject);

    return null;
  } catch (error) {
    console.error("Failed to extract SPIFFE ID:", error);
    return null;
  }
}

/**
 * Extract raw SID bytes from certificate extension.
 *
 * @param certPem - Certificate in PEM format
 * @returns SID bytes or null if not found
 */
export async function extractSidFromCert(certPem: string): Promise<Uint8Array | null> {
  const x509 = await loadX509Module();
  if (!x509) {
    throw new Error("@peculiar/x509 module not available");
  }

  try {
    const certDer = pemToDer(certPem);
    const cert = new x509.X509Certificate(certDer);

    const sidExtension = cert.getExtension(SID_OID);
    if (sidExtension) {
      return new Uint8Array(sidExtension);
    }

    return null;
  } catch (error) {
    console.error("Failed to extract SID:", error);
    return null;
  }
}

/**
 * Extract node ID from certificate extension.
 *
 * @param certPem - Certificate in PEM format
 * @returns Node ID string or null if not found
 */
export async function extractNodeIdFromCert(certPem: string): Promise<string | null> {
  const x509 = await loadX509Module();
  if (!x509) {
    throw new Error("@peculiar/x509 module not available");
  }

  try {
    const certDer = pemToDer(certPem);
    const cert = new x509.X509Certificate(certDer);

    const nodeIdExtension = cert.getExtension(NODE_ID_OID);
    if (nodeIdExtension) {
      const decoder = new TextDecoder();
      return decoder.decode(nodeIdExtension);
    }

    return null;
  } catch (error) {
    console.error("Failed to extract node ID:", error);
    return null;
  }
}

/**
 * Extract logical hosts from certificate private extension.
 *
 * @param certPem - Certificate in PEM format
 * @returns List of logical host addresses, empty if none found
 */
export async function extractLogicalHostsFromCert(certPem: string): Promise<string[]> {
  const x509 = await loadX509Module();
  if (!x509) {
    throw new Error("@peculiar/x509 module not available");
  }

  try {
    const certDer = pemToDer(certPem);
    const cert = new x509.X509Certificate(certDer);

    const logicalsExtension = cert.getExtension(LOGICALS_OID);
    if (logicalsExtension) {
      const decoder = new TextDecoder();
      const jsonStr = decoder.decode(logicalsExtension);
      return JSON.parse(jsonStr);
    }

    return [];
  } catch (error) {
    console.error("Failed to extract logical hosts:", error);
    return [];
  }
}

/**
 * Extract the SID string from a SPIFFE ID.
 *
 * @param spiffeId - SPIFFE ID in format spiffe://trust-domain/nodes/<sid>
 * @returns SID string (base62-encoded) or null if not a valid node SPIFFE ID
 */
export function extractSidFromSpiffeId(spiffeId: string): string | null {
  if (!spiffeId.startsWith("spiffe://")) {
    return null;
  }

  // Parse spiffe://trust-domain/nodes/<sid>
  const parts = spiffeId.split("/");
  if (parts.length >= 5 && parts[3] === "nodes") {
    return parts[4] ?? null; // The SID string (base62-encoded)
  }

  return null;
}

/**
 * Verify that the SID in the certificate matches the expected physical path.
 *
 * @param certPem - Certificate in PEM format
 * @param physicalPath - The expected physical path to verify against
 * @returns True if SID matches computed hash of physical path, False otherwise
 */
export async function verifyCertSidIntegrity(
  certPem: string,
  physicalPath: string
): Promise<boolean> {
  const sidBytes = await extractSidFromCert(certPem);
  if (!sidBytes) {
    return false;
  }

  try {
    const decoder = new TextDecoder();
    const certSid = decoder.decode(sidBytes);

    // Compute expected SID from physical path and compare
    // TODO: Import secureDigest from runtime
    // const expectedSid = secureDigest(physicalPath);
    // return certSid === expectedSid;

    console.log("Verifying SID integrity:", { certSid, physicalPath });
    return false; // Placeholder until secureDigest is available
  } catch (error) {
    console.error("Failed to verify SID integrity:", error);
    return false;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert PEM to DER format as ArrayBuffer.
 */
function pemToDer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN[^-]+-----/, "")
    .replace(/-----END[^-]+-----/, "")
    .replace(/\s/g, "");

  const bytes = base64ToBuffer(base64);
  // Create a new ArrayBuffer and copy the data
  const buffer = new ArrayBuffer(bytes.length);
  const view = new Uint8Array(buffer);
  view.set(bytes);
  return buffer;
}

/**
 * Convert base64 string to Uint8Array.
 */
function base64ToBuffer(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(base64, "base64");
  }

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert ArrayBuffer to base64 string.
 */
function bufferToBase64(buffer: ArrayBuffer): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buffer).toString("base64");
  }

  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/**
 * Format base64 string into 64-character lines.
 */
function formatPem(base64: string): string {
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.substring(i, Math.min(i + 64, base64.length)));
  }
  return lines.join("\n");
}
