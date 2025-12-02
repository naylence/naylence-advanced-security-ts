/**
 * Certificate client for requesting certificates from a CA signing service.
 *
 * Provides async HTTP client to request certificates from the CA signing service.
 */

import { AsnConvert } from "@peculiar/asn1-schema";
import { Certificate, Name, SubjectAlternativeName } from "@peculiar/asn1-x509";
import { X509Certificate } from "@peculiar/x509";
import type { CertificateInfo } from "./ca-types.js";
import { CertificateRequestError } from "./ca-types.js";
import { LOGICALS_OID, NODE_ID_OID, SID_OID } from "./oid-constants.js";

// Simple logger for now - TODO: integrate with runtime logging
const logger = {
  debug: (_event: string, _meta?: Record<string, unknown>) => {
    // console.log(`[DEBUG] ${event}`, meta);
  },
  error: (_event: string, _meta?: Record<string, unknown>) => {
    console.error(`[ERROR] ${_event}`, _meta);
  },
};

export const ENV_VAR_FAME_CA_SERVICE_URL = "FAME_CA_SERVICE_URL";

/**
 * HTTP connection grant for CA service.
 */
export interface HttpConnectionGrant {
  /** Base URL for the CA service */
  url: string;
}

/**
 * Certificate request response from CA service.
 */
export interface CertificateRequestResponse {
  /** Issued certificate in PEM format */
  certificatePem: string;

  /** Full certificate chain in PEM format */
  certificateChainPem: string;

  /** Certificate expiration time in ISO format */
  expiresAt?: string;
}

/**
 * Extract certificate information from a PEM certificate.
 *
 * Uses node-forge to parse X.509 certificates and extract metadata.
 *
 * @param _certPem - Certificate in PEM format (prefixed with underscore as currently unused)
 * @returns Certificate information object
 */
export function extractCertificateInfo(_certPem: string): CertificateInfo {
  try {
    const pemBlock = extractFirstCertificatePem(_certPem);
    if (!pemBlock) {
      throw new Error("certificate PEM block not found");
    }

    const certDer = pemToArrayBuffer(pemBlock);
    const certificate = new X509Certificate(certDer);
    const certificateRecord = certificate as unknown as Record<string, unknown>;
    const parsedCertificate = AsnConvert.parse(certDer, Certificate);

    const subject =
      readOptionalStringProperty(certificateRecord, "subject") ??
      formatDistinguishedName(parsedCertificate.tbsCertificate.subject);
    const issuer =
      readOptionalStringProperty(certificateRecord, "issuer") ??
      formatDistinguishedName(parsedCertificate.tbsCertificate.issuer);
    const serialNumber =
      readOptionalStringProperty(certificateRecord, "serialNumber") ??
      bytesToHex(parsedCertificate.tbsCertificate.serialNumber);
    const validFromDate =
      readOptionalDateProperty(certificateRecord, "notBefore") ??
      readValidityDate(parsedCertificate.tbsCertificate.validity.notBefore);
    const validUntilDate =
      readOptionalDateProperty(certificateRecord, "notAfter") ??
      readValidityDate(parsedCertificate.tbsCertificate.validity.notAfter);

    if (!validFromDate || !validUntilDate) {
      throw new Error("certificate validity period is missing");
    }

    const info: CertificateInfo = {
      subject,
      issuer,
      serialNumber,
      validFrom: validFromDate.toISOString(),
      validUntil: validUntilDate.toISOString(),
      status: "unknown",
    };

    const now = new Date();
    if (now < validFromDate) {
      info.status = "not_yet_valid";
    } else if (now > validUntilDate) {
      info.status = "expired";
    } else {
      info.status = "valid";
      const diffMs = validUntilDate.getTime() - now.getTime();
      info.daysRemaining = Math.floor(diffMs / (24 * 60 * 60 * 1000));
      const hoursRemainder = diffMs % (24 * 60 * 60 * 1000);
      info.hoursRemaining = Math.floor(hoursRemainder / (60 * 60 * 1000));
      const minutesRemainder = hoursRemainder % (60 * 60 * 1000);
      info.minutesRemaining = Math.floor(minutesRemainder / (60 * 1000));
    }

    const sanExtension = getExtensionValue(certificate, "2.5.29.17");
    if (sanExtension && toUint8Array(sanExtension).length > 0) {
      const san = AsnConvert.parse(sanExtension, SubjectAlternativeName);
      const altNames: string[] = [];
      for (const generalName of san) {
        const name = generalName as Record<string, unknown>;
        if (typeof name.uniformResourceIdentifier === "string") {
          altNames.push(name.uniformResourceIdentifier);
        } else if (typeof name.dNSName === "string") {
          altNames.push(name.dNSName);
        } else if (typeof name.rfc822Name === "string") {
          altNames.push(name.rfc822Name);
        } else if (name.iPAddress instanceof ArrayBuffer) {
          altNames.push(formatIpAddress(toUint8Array(name.iPAddress)));
        } else if (name.iPAddress && ArrayBuffer.isView(name.iPAddress)) {
          const view = name.iPAddress as ArrayBufferView;
          altNames.push(
            formatIpAddress(
              new Uint8Array(view.buffer, view.byteOffset, view.byteLength),
            ),
          );
        }
      }
      if (altNames.length > 0) {
        info.subjectAlternativeNames = altNames;
        const spiffe = altNames.find((value) => value.startsWith("spiffe://"));
        if (spiffe) {
          info.spiffeId = spiffe;
        }
      }
    }

    const sidExtension = getExtensionValue(certificate, SID_OID);
    if (sidExtension) {
      info.nodeSid = decodeUtf8(sidExtension);
    }

    const nodeIdExtension = getExtensionValue(certificate, NODE_ID_OID);
    if (nodeIdExtension) {
      info.nodeId = decodeUtf8(nodeIdExtension);
    }

    const logicalsExtension = getExtensionValue(certificate, LOGICALS_OID);
    if (logicalsExtension) {
      try {
        const logicalsJson = decodeUtf8(logicalsExtension);
        const parsed = JSON.parse(logicalsJson);
        if (Array.isArray(parsed)) {
          info.logicalHosts = parsed.filter(
            (entry: unknown): entry is string => typeof entry === "string",
          );
        }
      } catch {
        // Ignore malformed extension payload – certificate remains valid.
      }
    }

    return info;
  } catch (error) {
    return {
      subject: "",
      issuer: "",
      serialNumber: "",
      validFrom: "",
      validUntil: "",
      status: "unknown",
      error: `Failed to parse certificate: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * Format certificate information in human-readable format.
 *
 * @param certPem - Certificate in PEM format
 * @param certType - Type description for logging (e.g., "Certificate", "CA Certificate")
 * @returns Formatted string with certificate details
 */
export function formatCertificateInfo(
  certPem: string,
  certType: string = "Certificate",
): string {
  const info = extractCertificateInfo(certPem);

  if (info.error) {
    return `=== ${certType} Information ===\n${info.error}`;
  }

  const lines = [
    `=== ${certType} Information ===`,
    `Subject: ${info.subject}`,
    `Issuer: ${info.issuer}`,
    `Serial Number: ${info.serialNumber}`,
    `Valid From: ${info.validFrom}`,
    `Valid Until: ${info.validUntil}`,
  ];

  if (info.subjectAlternativeNames?.length) {
    lines.push(
      `Subject Alternative Names: ${info.subjectAlternativeNames.join(", ")}`,
    );
  }

  if (info.spiffeId) {
    lines.push(`SPIFFE ID: ${info.spiffeId}`);
  }

  if (info.nodeSid) {
    lines.push(`Node SID: ${info.nodeSid}`);
  }

  if (info.nodeId) {
    lines.push(`Node ID: ${info.nodeId}`);
  }

  if (info.logicalHosts?.length) {
    lines.push(`Logical Hosts: ${info.logicalHosts.join(", ")}`);
  }

  if (info.status === "valid") {
    const pieces: string[] = [];
    if (typeof info.daysRemaining === "number" && info.daysRemaining > 0) {
      pieces.push(`${info.daysRemaining} days`);
    }
    if (typeof info.hoursRemaining === "number" && info.hoursRemaining > 0) {
      pieces.push(`${info.hoursRemaining} hours`);
    }
    if (
      typeof info.minutesRemaining === "number" &&
      info.minutesRemaining > 0 &&
      pieces.length === 0
    ) {
      pieces.push(`${info.minutesRemaining} minutes`);
    }
    if (pieces.length > 0) {
      lines.push(`Status: Valid (${pieces.join(", ")})`);
    } else {
      lines.push("Status: Valid");
    }
  } else if (info.status === "expired") {
    lines.push("Status: Expired");
  } else if (info.status === "not_yet_valid") {
    lines.push("Status: Not yet valid");
  } else {
    lines.push("Status: Unknown");
  }

  return lines.join("\n");
}

function extractFirstCertificatePem(pem: string): string | null {
  const match = pem.match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/,
  );
  return match ? match[0] : null;
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  if (typeof Buffer !== "undefined") {
    const buffer = Buffer.from(base64, "base64");
    const array = buffer.buffer.slice(
      buffer.byteOffset,
      buffer.byteOffset + buffer.byteLength,
    );
    return array;
  }

  if (typeof globalThis.atob === "function") {
    const binary = globalThis.atob(base64);
    const length = binary.length;
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  throw new Error("Base64 decoding not supported in this environment");
}

function formatIpAddress(bytes: Uint8Array): string {
  if (bytes.length === 4) {
    return Array.from(bytes).join(".");
  }

  if (bytes.length === 16) {
    const hextets: string[] = [];
    for (let index = 0; index < 16; index += 2) {
      const value = (bytes[index]! << 8) | bytes[index + 1]!;
      hextets.push(value.toString(16));
    }
    return hextets.join(":");
  }

  return Array.from(bytes)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function toUint8Array(source: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source);
  }
  return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

function decodeUtf8(data: ArrayBuffer): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(data);
  }
  if (typeof Buffer !== "undefined") {
    const buffer = Buffer.from(data);
    return buffer.toString("utf8");
  }
  throw new Error("TextDecoder not available in this environment");
}

function getExtensionValue(
  certificate: X509Certificate,
  oid: string,
): ArrayBuffer | null {
  const candidate = certificate as unknown as {
    getExtension?: (oid: string) => unknown;
    extensions?: unknown;
  };

  if (typeof candidate.getExtension === "function") {
    const result = candidate.getExtension(oid);
    const buffer = tryExtractExtensionBuffer(result);
    if (buffer) {
      return buffer;
    }
  }

  const { extensions } = candidate;
  if (extensions) {
    const iterable = toIterable(extensions);
    for (const entry of iterable) {
      const extensionRecord = entry as { oid?: string } | null | undefined;
      if (!extensionRecord || extensionRecord.oid !== oid) {
        continue;
      }
      const buffer = tryExtractExtensionBuffer(entry);
      if (buffer) {
        return buffer;
      }
    }
  }

  return null;
}

function readOptionalStringProperty(
  source: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = source[key];
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return undefined;
}

function readOptionalDateProperty(
  source: Record<string, unknown>,
  key: string,
): Date | undefined {
  const value = source[key];
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === "number" || typeof value === "string") {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) {
      return date;
    }
  }
  return undefined;
}

function readValidityDate(candidate: unknown): Date | undefined {
  if (!candidate) {
    return undefined;
  }
  if (candidate instanceof Date) {
    return candidate;
  }
  if (
    typeof candidate === "object" &&
    candidate !== null &&
    (candidate as { utcTime?: unknown; generalizedTime?: unknown })
  ) {
    const timeObject = candidate as {
      utcTime?: unknown;
      generalizedTime?: unknown;
    };
    if (timeObject.utcTime instanceof Date) {
      return timeObject.utcTime;
    }
    if (timeObject.generalizedTime instanceof Date) {
      return timeObject.generalizedTime;
    }
  }
  return undefined;
}

function formatDistinguishedName(name: Name): string {
  const rdns = Array.from(name);
  if (rdns.length === 0) {
    return "";
  }
  return rdns
    .map((rdn) =>
      Array.from(rdn)
        .map((attribute) =>
          `${oidToLabel(attribute.type)}=${attribute.value.toString()}`,
        )
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

function bytesToHex(data: ArrayBuffer | ArrayBufferView): string {
  const view = toUint8Array(data);
  if (view.length === 0) {
    return "";
  }
  return Array.from(view)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function tryExtractExtensionBuffer(source: unknown): ArrayBuffer | null {
  if (!source) {
    return null;
  }

  if (isArrayBufferLike(source)) {
    return cloneArrayBuffer(source);
  }

  if (typeof source === "object") {
    const record = source as Record<string, unknown>;
    const directValue = record.value;
    if (isArrayBufferLike(directValue)) {
      return cloneArrayBuffer(directValue);
    }

    const asn = record.asn as Record<string, unknown> | undefined;
    if (asn) {
      const extnValue = asn.extnValue as unknown;
      if (isArrayBufferLike(extnValue)) {
        return cloneArrayBuffer(extnValue);
      }
      if (
        extnValue &&
        typeof extnValue === "object" &&
        isArrayBufferLike((extnValue as Record<string, unknown>).buffer)
      ) {
        return cloneArrayBuffer(
          (extnValue as Record<string, unknown>).buffer as ArrayBuffer,
        );
      }
    }
  }

  return null;
}

function isArrayBufferLike(value: unknown): value is ArrayBuffer | ArrayBufferView {
  return value instanceof ArrayBuffer || ArrayBuffer.isView(value);
}

function cloneArrayBuffer(value: ArrayBuffer | ArrayBufferView): ArrayBuffer {
  const view = toUint8Array(value);
  if (
    view.byteOffset === 0 &&
    view.byteLength === view.buffer.byteLength &&
    view.buffer instanceof ArrayBuffer
  ) {
    return view.buffer;
  }
  return view.slice().buffer;
}

function toIterable(value: unknown): Iterable<unknown> {
  if (typeof value === "object" && value && Symbol.iterator in value) {
    return value as Iterable<unknown>;
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [];
}

/**
 * Client for requesting certificates from a CA signing service.
 */
export class CAServiceClient {
  private readonly connectionGrant: HttpConnectionGrant;
  private readonly timeoutSeconds: number;
  private authHeader: string | null = null;

  /**
   * Create a new CA service client.
   *
   * @param connectionGrant - HTTP connection grant with CA service URL
   * @param timeoutSeconds - Request timeout in seconds (default: 30)
   */
  constructor(
    connectionGrant: HttpConnectionGrant,
    timeoutSeconds: number = 30.0,
  ) {
    if (!connectionGrant || typeof connectionGrant.url !== "string") {
      throw new Error("connectionGrant must have a valid url property");
    }

    this.connectionGrant = connectionGrant;
    this.timeoutSeconds = timeoutSeconds;
  }

  /**
   * Set the authorization header for outbound requests.
   *
   * @param authHeader - Authorization header value (e.g., "Bearer token")
   */
  setAuthHeader(authHeader: string): void {
    this.authHeader = authHeader;
  }

  /**
   * Request a certificate from the CA service.
   *
   * @param csrPem - Certificate Signing Request in PEM format
   * @param requesterId - ID of the node requesting the certificate
   * @param physicalPath - Physical path for the node (optional)
   * @param logicals - Logicals the node will serve (optional)
   * @returns Tuple of [certificatePem, certificateChainPem]
   * @throws {CertificateRequestError} If the request fails
   */
  async requestCertificate(
    csrPem: string,
    requesterId: string,
    physicalPath?: string,
    logicals?: string[],
  ): Promise<[string, string]> {
    const requestData = {
      csr_pem: csrPem,
      requester_id: requesterId,
      physical_path: physicalPath,
      logicals: logicals || [],
    };

    const url = `${this.connectionGrant.url.replace(/\/$/, "")}/sign`;

    logger.debug("requesting_certificate", {
      requester_id: requesterId,
      ca_service_url: url,
      physical_path: physicalPath,
      logicals,
    });

    // Prepare headers
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };

    if (this.authHeader) {
      headers["Authorization"] = this.authHeader;
    }

    try {
      // Create abort controller for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        this.timeoutSeconds * 1000,
      );

      try {
        const response = await fetch(url, {
          method: "POST",
          headers,
          body: JSON.stringify(requestData),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (response.ok) {
          const result = await response.json();
          const certificatePem: string = result.certificate_pem;
          const certificateChainPem: string =
            result.certificate_chain_pem || certificatePem;

          logger.debug("certificate_request_successful", {
            requester_id: requesterId,
            expires_at: result.expires_at,
          });

          // Extract and log certificate information with structured logging
          const certInfo = extractCertificateInfo(certificatePem);
          logger.debug("certificate_details", {
            requester_id: requesterId,
            certificate_type: "issued_certificate",
            ...certInfo,
          });

          // If we have a separate certificate chain, also log its details
          if (certificateChainPem !== certificatePem) {
            // Extract individual certificates from the chain
            const chainCerts = certificateChainPem
              .split("-----END CERTIFICATE-----\n")
              .slice(0, -1);

            for (let i = 0; i < chainCerts.length; i++) {
              const certBlock = chainCerts[i];
              if (certBlock && certBlock.trim()) {
                const certPemBlock = certBlock + "-----END CERTIFICATE-----\n";

                if (i === 0) {
                  // First cert in chain is usually the issued certificate
                  if (certPemBlock.trim() !== certificatePem.trim()) {
                    const chainCertInfo = extractCertificateInfo(certPemBlock);
                    logger.debug("certificate_chain_details", {
                      requester_id: requesterId,
                      certificate_type: "certificate_chain",
                      chain_index: i,
                      ...chainCertInfo,
                    });
                  }
                } else {
                  // Subsequent certs are intermediate/root CAs
                  const caCertInfo = extractCertificateInfo(certPemBlock);
                  logger.debug("certificate_chain_details", {
                    requester_id: requesterId,
                    certificate_type: "ca_certificate",
                    chain_index: i,
                    ...caCertInfo,
                  });
                }
              }
            }
          }

          return [certificatePem, certificateChainPem];
        } else {
          let errorDetail = "Unknown error";
          try {
            const bodyText = await response.text();
            try {
              const errorData = JSON.parse(bodyText);
              errorDetail = errorData.detail || bodyText;
            } catch {
              errorDetail = bodyText;
            }
          } catch {
            // Body read failed entirely
            errorDetail = `HTTP ${response.status}`;
          }

          logger.error("certificate_request_failed", {
            requester_id: requesterId,
            status_code: response.status,
            error: errorDetail,
          });

          throw new CertificateRequestError(
            `Certificate request failed (HTTP ${response.status}): ${errorDetail}`,
          );
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      if (error instanceof CertificateRequestError) {
        throw error;
      }

      if (error instanceof Error && error.name === "AbortError") {
        logger.error("certificate_request_timeout", {
          requester_id: requesterId,
          timeout_seconds: this.timeoutSeconds,
        });
        throw new CertificateRequestError(
          `Certificate request timed out after ${this.timeoutSeconds} seconds`,
        );
      }

      logger.error("certificate_request_network_error", {
        requester_id: requesterId,
        error: String(error),
      });
      throw new CertificateRequestError(
        `Network error requesting certificate: ${error}`,
      );
    }
  }
}
