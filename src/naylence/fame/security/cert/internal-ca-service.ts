/**
 * Certificate Authority signing service for node certificates.
 *
 * Provides in-process API for issuing certificates with node physical
 * and host-like logical address information using SPIFFE-compliant identities.
 */

import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
  AlgorithmIdentifier,
  AttributeTypeAndValue,
  AttributeValue,
  AuthorityKeyIdentifier,
  BasicConstraints,
  Certificate,
  Extension,
  Extensions,
  ExtendedKeyUsage,
  GeneralName,
  GeneralSubtree,
  GeneralSubtrees,
  KeyIdentifier,
  KeyUsage as X509KeyUsage,
  KeyUsageFlags,
  Name,
  NameConstraints,
  RelativeDistinguishedName,
  SubjectAlternativeName,
  SubjectPublicKeyInfo,
  SubjectKeyIdentifier,
  TBSCertificate,
  Validity,
  Version,
  id_ce_authorityKeyIdentifier,
  id_ce_basicConstraints,
  id_ce_extKeyUsage,
  id_ce_keyUsage,
  id_ce_nameConstraints,
  id_ce_subjectAltName,
  id_ce_subjectKeyIdentifier,
  id_kp_clientAuth,
  id_kp_serverAuth,
} from "@peculiar/asn1-x509";
import { CertificationRequest } from "@peculiar/asn1-csr";
import { secureDigest, validateHostLogical } from "@naylence/runtime";
import type {
  CertificateIssuanceResponse,
  CertificateSigningRequest,
} from "./ca-types.js";
import { CAService } from "./ca-types.js";

// Certificate extension OIDs (using placeholder PEN)
export const SID_OID = "1.3.6.1.4.1.58530.1";
export const LOGICALS_OID = "1.3.6.1.4.1.58530.2";
export const NODE_ID_OID = "1.3.6.1.4.1.58530.4";
const ED25519_OID = "1.3.101.112";

/**
 * X.509 module interface (lazy-loaded).
 */
interface X509Module {
  X509Certificate: new (rawData: BufferSource) => {
    readonly rawData: ArrayBuffer;
    readonly subject: string;
    readonly issuer: string;
    readonly serialNumber: string;
    readonly notBefore: Date;
    readonly notAfter: Date;
    readonly publicKey: CryptoKey | Promise<CryptoKey>;
    getExtension(oid: string): ArrayBuffer | null;
  };
}

let x509ModulePromise: Promise<X509Module | null> | null = null;

type X509CertificateInstance = InstanceType<X509Module["X509Certificate"]>;
let cryptoPromise: Promise<Crypto> | null = null;
let subtleCryptoPromise: Promise<SubtleCrypto> | null = null;

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

async function ensureCrypto(): Promise<Crypto> {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }

  if (!cryptoPromise) {
    if (
      typeof process !== "undefined" &&
      typeof process.versions?.node === "string"
    ) {
      cryptoPromise = import("crypto").then((cryptoModule) => {
        const webcrypto = (cryptoModule as unknown as { webcrypto?: Crypto })
          .webcrypto;
        if (!webcrypto || !webcrypto.subtle) {
          throw new Error(
            "WebCrypto API is not available in this Node.js runtime",
          );
        }

        (globalThis as Record<string, unknown>).crypto = webcrypto;
        return webcrypto;
      });
    } else {
      cryptoPromise = Promise.reject(
        new Error("WebCrypto API is not available in this environment"),
      );
    }
  }

  return cryptoPromise;
}

async function getSubtleCrypto(): Promise<SubtleCrypto> {
  if (!subtleCryptoPromise) {
    subtleCryptoPromise = ensureCrypto().then(
      (cryptoImpl) => cryptoImpl.subtle,
    );
  }

  return subtleCryptoPromise;
}

async function importEd25519PrivateKey(
  pem: string,
  keyUsages: KeyUsage[] = ["sign"],
): Promise<CryptoKey> {
  const subtle = await getSubtleCrypto();
  const der = pemToDer(pem);

  try {
    return await subtle.importKey(
      "pkcs8",
      der,
      { name: "Ed25519" },
      false,
      keyUsages,
    );
  } catch (error) {
    throw new Error(
      `Failed to import Ed25519 private key: ${(error as Error).message}`,
    );
  }
}

async function importEd25519PublicKey(
  pem: string,
  keyUsages: KeyUsage[] = ["verify"],
): Promise<CryptoKey> {
  const subtle = await getSubtleCrypto();
  const der = pemToDer(pem);

  try {
    return await subtle.importKey(
      "spki",
      der,
      { name: "Ed25519" },
      true,
      keyUsages,
    );
  } catch (error) {
    throw new Error(
      `Failed to import Ed25519 public key: ${(error as Error).message}`,
    );
  }
}

async function computeKeyIdentifier(
  key: KeyIdentifierSource,
): Promise<Uint8Array> {
  const subtle = await getSubtleCrypto();
  let spki: ArrayBuffer;
  if (key instanceof ArrayBuffer) {
    spki = key;
  } else if (ArrayBuffer.isView(key)) {
    const view = new Uint8Array(key.buffer, key.byteOffset, key.byteLength);
    spki = view.slice().buffer;
  } else {
    spki = await subtle.exportKey("spki", key);
  }
  const digest = await subtle.digest("SHA-256", spki);
  return new Uint8Array(digest);
}

function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  return new Uint8Array(view).buffer;
}

function serializeAsn(value: unknown): ArrayBuffer {
  return AsnConvert.serialize(value);
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const normalized = hex.length % 2 === 0 ? hex : `0${hex}`;
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    const byte = normalized.slice(i * 2, i * 2 + 2);
    bytes[i] = Number.parseInt(byte, 16);
  }
  return bytes.buffer;
}

interface CertificateBuildOptions {
  subject: Name;
  issuer: Name;
  subjectPublicKey: CryptoKey;
  signingKey: CryptoKey;
  notBefore: Date;
  notAfter: Date;
  extensions: Array<{ type: string; critical: boolean; value: ArrayBuffer }>;
}

type KeyIdentifierSource = CryptoKey | ArrayBuffer | ArrayBufferView;

async function createEd25519Certificate(
  options: CertificateBuildOptions,
): Promise<ArrayBuffer> {
  const subtle = await getSubtleCrypto();

  await ensureCrypto();
  const serialHex = generateSerialNumber();

  const issuerName = cloneName(options.issuer);
  const subjectName = cloneName(options.subject);

  const subjectSpki = await subtle.exportKey("spki", options.subjectPublicKey);
  const subjectPublicKeyInfo = AsnConvert.parse(
    subjectSpki,
    SubjectPublicKeyInfo,
  );
  subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({
    algorithm: ED25519_OID,
  });

  const signatureAlgorithm = new AlgorithmIdentifier({
    algorithm: ED25519_OID,
  });

  const extensions = options.extensions?.length
    ? new Extensions(
        options.extensions.map(
          (ext) =>
            new Extension({
              extnID: ext.type,
              critical: ext.critical,
              extnValue: new OctetString(ext.value),
            }),
        ),
      )
    : undefined;

  const tbsCertificate = new TBSCertificate({
    version: Version.v3,
    serialNumber: hexToArrayBuffer(serialHex),
    signature: signatureAlgorithm,
    issuer: issuerName,
    validity: new Validity({
      notBefore: options.notBefore,
      notAfter: options.notAfter,
    }),
    subject: subjectName,
    subjectPublicKeyInfo,
    extensions,
  });

  const tbsDer = AsnConvert.serialize(tbsCertificate);
  const signature = await subtle.sign("Ed25519", options.signingKey, tbsDer);

  const certificate = new Certificate({
    tbsCertificate,
    signatureAlgorithm,
    signatureValue: signature,
  });

  certificate.tbsCertificateRaw = tbsDer;

  return AsnConvert.serialize(certificate);
}

function derToPem(der: ArrayBuffer, label: string): string {
  const base64 = bufferToBase64(der);
  return `-----BEGIN ${label}-----\n${formatPem(base64)}\n-----END ${label}-----\n`;
}

function addDays(base: Date, days: number): Date {
  const result = new Date(base.getTime());
  result.setUTCDate(result.getUTCDate() + days);
  return result;
}

function generateSerialNumber(bytes: number = 16): string {
  const cryptoImpl = (globalThis as unknown as { crypto?: Crypto }).crypto;
  if (!cryptoImpl) {
    throw new Error("Crypto API not initialized");
  }

  const random = new Uint8Array(bytes);
  cryptoImpl.getRandomValues(random);
  random[0]! &= 0x7f;
  return Array.from(random, (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

function getFameRootDomain(): string {
  if (typeof process !== "undefined" && process.env?.FAME_ROOT) {
    return process.env.FAME_ROOT;
  }

  return "fame.fabric";
}

const OID_COMMON_NAME = "2.5.4.3";
const OID_ORGANIZATIONAL_UNIT = "2.5.4.11";
const OID_ORGANIZATION = "2.5.4.10";

function createRelativeDistinguishedName(
  oid: string,
  value: string,
): RelativeDistinguishedName {
  return new RelativeDistinguishedName([
    new AttributeTypeAndValue({
      type: oid,
      value: new AttributeValue({ utf8String: value }),
    }),
  ]);
}

function buildCertificateName(
  commonName: string,
  organization?: string,
  organizationalUnit?: string,
): Name {
  const rdns: RelativeDistinguishedName[] = [
    createRelativeDistinguishedName(OID_COMMON_NAME, commonName),
  ];
  if (organizationalUnit) {
    rdns.push(
      createRelativeDistinguishedName(
        OID_ORGANIZATIONAL_UNIT,
        organizationalUnit,
      ),
    );
  }
  if (organization) {
    rdns.push(createRelativeDistinguishedName(OID_ORGANIZATION, organization));
  }
  return new Name(rdns);
}

function cloneName(name: Name): Name {
  return AsnConvert.parse(AsnConvert.serialize(name), Name);
}

interface CertificateIdentity {
  name: Name;
  subjectPublicKeyInfo: ArrayBuffer;
}

function getCertificateIdentity(
  cert: X509CertificateInstance,
): CertificateIdentity {
  const parsed = AsnConvert.parse(cert.rawData, Certificate);
  return {
    name: cloneName(parsed.tbsCertificate.subject),
    subjectPublicKeyInfo: AsnConvert.serialize(
      parsed.tbsCertificate.subjectPublicKeyInfo,
    ),
  };
}

async function buildCaExtensions(
  subjectPublicKey: CryptoKey,
  issuerPublicKey: KeyIdentifierSource,
  options: { pathLength: number | null; permittedDnsDomains?: string[] },
): Promise<Array<{ type: string; critical: boolean; value: ArrayBuffer }>> {
  const extensions: Array<{
    type: string;
    critical: boolean;
    value: ArrayBuffer;
  }> = [];

  const basicConstraints = new BasicConstraints({ cA: true });
  if (options.pathLength !== null && options.pathLength !== undefined) {
    basicConstraints.pathLenConstraint = options.pathLength;
  }
  extensions.push({
    type: id_ce_basicConstraints,
    critical: true,
    value: serializeAsn(basicConstraints),
  });

  const keyUsageFlags =
    KeyUsageFlags.digitalSignature |
    KeyUsageFlags.keyCertSign |
    KeyUsageFlags.cRLSign;
  extensions.push({
    type: id_ce_keyUsage,
    critical: true,
    value: serializeAsn(new X509KeyUsage(keyUsageFlags)),
  });

  const subjectKeyId = await computeKeyIdentifier(subjectPublicKey);
  extensions.push({
    type: id_ce_subjectKeyIdentifier,
    critical: false,
    value: serializeAsn(new SubjectKeyIdentifier(subjectKeyId)),
  });

  const authorityKeyId = await computeKeyIdentifier(issuerPublicKey);
  extensions.push({
    type: id_ce_authorityKeyIdentifier,
    critical: false,
    value: serializeAsn(
      new AuthorityKeyIdentifier({
        keyIdentifier: new KeyIdentifier(authorityKeyId),
      }),
    ),
  });

  if (options.permittedDnsDomains?.length) {
    const permittedSubtrees = new GeneralSubtrees(
      options.permittedDnsDomains.map(
        (domain) =>
          new GeneralSubtree({ base: new GeneralName({ dNSName: domain }) }),
      ),
    );
    const constraints = new NameConstraints({ permittedSubtrees });
    extensions.push({
      type: id_ce_nameConstraints,
      critical: true,
      value: serializeAsn(constraints),
    });
  }

  return extensions;
}

async function buildLeafExtensions(
  publicKey: CryptoKey,
  nodeSid: string,
  nodeId: string,
  spiffeId: string,
  logicalHosts: string[],
  issuerPublicKey: KeyIdentifierSource,
): Promise<Array<{ type: string; critical: boolean; value: ArrayBuffer }>> {
  const extensions: Array<{
    type: string;
    critical: boolean;
    value: ArrayBuffer;
  }> = [];

  extensions.push({
    type: id_ce_subjectAltName,
    critical: false,
    value: serializeAsn(
      new SubjectAlternativeName([
        new GeneralName({ uniformResourceIdentifier: spiffeId }),
      ]),
    ),
  });

  const keyUsageFlags = KeyUsageFlags.digitalSignature;
  extensions.push({
    type: id_ce_keyUsage,
    critical: true,
    value: serializeAsn(new X509KeyUsage(keyUsageFlags)),
  });

  extensions.push({
    type: id_ce_extKeyUsage,
    critical: false,
    value: serializeAsn(
      new ExtendedKeyUsage([id_kp_clientAuth, id_kp_serverAuth]),
    ),
  });

  const subjectKeyId = await computeKeyIdentifier(publicKey);
  extensions.push({
    type: id_ce_subjectKeyIdentifier,
    critical: false,
    value: serializeAsn(new SubjectKeyIdentifier(subjectKeyId)),
  });

  const authorityKeyId = await computeKeyIdentifier(issuerPublicKey);
  extensions.push({
    type: id_ce_authorityKeyIdentifier,
    critical: false,
    value: serializeAsn(
      new AuthorityKeyIdentifier({
        keyIdentifier: new KeyIdentifier(authorityKeyId),
      }),
    ),
  });

  extensions.push({
    type: SID_OID,
    critical: false,
    value: toArrayBuffer(new TextEncoder().encode(nodeSid)),
  });

  extensions.push({
    type: NODE_ID_OID,
    critical: false,
    value: toArrayBuffer(new TextEncoder().encode(nodeId)),
  });

  if (logicalHosts.length) {
    const logicalsJson = JSON.stringify(logicalHosts);
    extensions.push({
      type: LOGICALS_OID,
      critical: false,
      value: toArrayBuffer(new TextEncoder().encode(logicalsJson)),
    });
  }

  return extensions;
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
  private readonly rootCertPem: string;
  private readonly rootKeyPem: string;
  private readonly intermediateCertPem?: string;
  private readonly intermediateKeyPem?: string;

  private rootCert?: X509CertificateInstance;
  private rootKey?: CryptoKey;
  private signingCert?: X509CertificateInstance;
  private signingKey?: CryptoKey;

  constructor(options: CASigningServiceOptions) {
    super();

    this.rootCertPem = options.rootCertPem;
    this.rootKeyPem = options.rootKeyPem;
    this.intermediateCertPem = options.intermediateCertPem;
    this.intermediateKeyPem = options.intermediateKeyPem;
  }

  private async ensureRootMaterials(): Promise<X509Module> {
    const x509 = await loadX509Module();
    if (!x509) {
      throw new Error("@peculiar/x509 module not available");
    }

    if (!this.rootCert) {
      this.rootCert = new x509.X509Certificate(pemToDer(this.rootCertPem));
    }

    if (!this.rootKey) {
      this.rootKey = await importEd25519PrivateKey(this.rootKeyPem);
    }

    return x509;
  }

  private async ensureSigningMaterials(): Promise<X509Module> {
    const x509 = await this.ensureRootMaterials();

    if (this.intermediateCertPem && this.intermediateKeyPem) {
      if (!this.signingCert) {
        this.signingCert = new x509.X509Certificate(
          pemToDer(this.intermediateCertPem),
        );
      }

      if (!this.signingKey) {
        this.signingKey = await importEd25519PrivateKey(
          this.intermediateKeyPem,
        );
      }
    } else {
      this.signingCert = this.rootCert;
      this.signingKey = this.rootKey;
    }

    return x509;
  }

  private getRootCertificate(): X509CertificateInstance {
    if (!this.rootCert) {
      throw new Error("Root certificate not initialized");
    }
    return this.rootCert;
  }

  private getRootKey(): CryptoKey {
    if (!this.rootKey) {
      throw new Error("Root private key not initialized");
    }
    return this.rootKey;
  }

  private getSigningCertificate(): X509CertificateInstance {
    if (!this.signingCert) {
      throw new Error("Signing certificate not initialized");
    }
    return this.signingCert;
  }

  private getSigningKey(): CryptoKey {
    if (!this.signingKey) {
      throw new Error("Signing key not initialized");
    }
    return this.signingKey;
  }

  /**
   * Issue a certificate from a CSR.
   *
   * Parses the PKCS#10 CSR, extracts the public key, calculates node SID,
   * and signs a certificate. Mirrors Python's default_ca_service.issue_certificate.
   *
   * @param csr - Certificate signing request
   * @returns Certificate issuance response with the signed certificate
   */
  async issueCertificate(
    csr: CertificateSigningRequest,
  ): Promise<CertificateIssuanceResponse> {
    // Parse PKCS#10 CSR to extract SubjectPublicKeyInfo
    const csrDer = pemToDer(csr.csrPem);
    const certRequest = AsnConvert.parse(csrDer, CertificationRequest);
    const subjectPublicKeyInfo =
      certRequest.certificationRequestInfo.subjectPKInfo;

    // Convert SubjectPublicKeyInfo to PEM format
    const publicKeyDer = AsnConvert.serialize(subjectPublicKeyInfo);
    const publicKeyPem = derToPem(publicKeyDer, "PUBLIC KEY");

    // Determine node SID and physical path (mirrors Python logic)
    const physicalPath = csr.physicalPath || `/unknown/${csr.requesterId}`;
    const nodeSid = secureDigest(physicalPath);
    const logicals = csr.logicals || [];

    // Issue the certificate (short-lived: 1 day)
    const certificatePem = await this.signNodeCert(
      publicKeyPem,
      csr.requesterId, // Use requesterId as node_id
      nodeSid,
      physicalPath,
      logicals,
      1, // TTL: 1 day (matches Python)
      undefined, // Use default SPIFFE trust domain
    );

    // Parse certificate to get expiration
    const certDer = pemToDer(certificatePem);
    const cert = AsnConvert.parse(certDer, Certificate);
    const notAfter = cert.tbsCertificate.validity.notAfter.getTime();
    const expiresAt = new Date(notAfter).toISOString();

    return {
      certificatePem,
      expiresAt,
    };
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
    spiffeTrustDomain: string = "naylence.fame",
  ): Promise<string> {
    await this.ensureSigningMaterials();
    const signingCert = this.getSigningCertificate();
    const signingKey = this.getSigningKey();

    const expectedSid = secureDigest(physicalPath);
    if (expectedSid !== nodeSid) {
      throw new Error(
        "Provided SID does not match the computed SID for the physical path",
      );
    }

    const logicalHosts = logicals ?? [];
    for (const logical of logicalHosts) {
      const [valid, error] = validateHostLogical(logical);
      if (!valid) {
        throw new Error(
          `Invalid logical host '${logical}': ${error ?? "unknown error"}`,
        );
      }
    }

    await ensureCrypto();

    const publicKey = await importEd25519PublicKey(publicKeyPem, ["verify"]);
    const issuerIdentity = getCertificateIdentity(signingCert);

    const now = new Date();
    const notBefore = new Date(now.getTime() - 60_000);
    const notAfter = addDays(now, ttlDays);

    const spiffeId = `spiffe://${spiffeTrustDomain}/nodes/${nodeSid}`;
    const extensions = await buildLeafExtensions(
      publicKey,
      nodeSid,
      nodeId,
      spiffeId,
      logicalHosts,
      issuerIdentity.subjectPublicKeyInfo,
    );

    const issuerName = issuerIdentity.name;
    const subjectName = new Name([]); // SPIFFE X.509-SVIDs require an empty subject DN

    const certDer = await createEd25519Certificate({
      subject: subjectName,
      issuer: issuerName,
      subjectPublicKey: publicKey,
      signingKey,
      notBefore,
      notAfter,
      extensions,
    });

    return derToPem(certDer, "CERTIFICATE");
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
    ttlDays: number = 1825, // 5 years default
  ): Promise<string> {
    await this.ensureRootMaterials();
    const rootCert = this.getRootCertificate();
    const rootKey = this.getRootKey();

    await ensureCrypto();

    const subjectPublicKey = await importEd25519PublicKey(publicKeyPem);

    const now = new Date();
    const notBefore = new Date(now.getTime() - 60_000);
    const notAfter = addDays(now, ttlDays);

    const subjectName = buildCertificateName(
      caName,
      "Naylence Fame",
      "Fame Intermediate CAs",
    );
    const issuerIdentity = getCertificateIdentity(rootCert);

    const extensions = await buildCaExtensions(
      subjectPublicKey,
      issuerIdentity.subjectPublicKeyInfo,
      {
        pathLength: 0,
        permittedDnsDomains: permittedPaths.length
          ? [getFameRootDomain()]
          : undefined,
      },
    );

    const certDer = await createEd25519Certificate({
      subject: subjectName,
      issuer: issuerIdentity.name,
      subjectPublicKey,
      signingKey: rootKey,
      notBefore,
      notAfter,
      extensions,
    });

    return derToPem(certDer, "CERTIFICATE");
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
  const subtle = await getSubtleCrypto();
  await ensureCrypto();

  const keyPair = await subtle.generateKey(
    {
      name: "Ed25519",
      namedCurve: "Ed25519",
    } as EcKeyGenParams,
    true,
    ["sign", "verify"],
  );

  const privateKeyDer = await subtle.exportKey("pkcs8", keyPair.privateKey);
  const publicKeyDer = await subtle.exportKey("spki", keyPair.publicKey);

  const rootKeyPem = derToPem(privateKeyDer, "PRIVATE KEY");
  const publicKeyPem = derToPem(publicKeyDer, "PUBLIC KEY");

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = addDays(now, 365 * 20);

  const subjectName = buildCertificateName(
    "Fame Test Root CA",
    "Naylence Fame",
  );
  const extensions = await buildCaExtensions(
    keyPair.publicKey,
    keyPair.publicKey,
    { pathLength: null },
  );

  const certDer = await createEd25519Certificate({
    subject: subjectName,
    issuer: subjectName,
    subjectPublicKey: keyPair.publicKey,
    signingKey: keyPair.privateKey,
    notBefore,
    notAfter,
    extensions,
  });

  const rootCertPem = derToPem(certDer, "CERTIFICATE");

  return [rootCertPem, rootKeyPem, publicKeyPem];
}

/**
 * Extract SPIFFE ID from certificate SAN.
 *
 * @param certPem - Certificate in PEM format
 * @returns SPIFFE ID string or null if not found
 */
export async function extractSpiffeIdFromCert(
  certPem: string,
): Promise<string | null> {
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
export async function extractSidFromCert(
  certPem: string,
): Promise<Uint8Array | null> {
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
export async function extractNodeIdFromCert(
  certPem: string,
): Promise<string | null> {
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
export async function extractLogicalHostsFromCert(
  certPem: string,
): Promise<string[]> {
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
  physicalPath: string,
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
