/**
 * Certificate client for requesting certificates from a CA signing service.
 *
 * Provides async HTTP client to request certificates from the CA signing service.
 */

import type { CertificateInfo } from "./ca-types.js";
import { CertificateRequestError } from "./ca-types.js";

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
    // TODO: Implement using node-forge or similar library
    // For now, return a placeholder
    return {
      subject: "TODO: Parse certificate",
      issuer: "TODO: Parse certificate",
      serialNumber: "TODO",
      validFrom: new Date().toISOString(),
      validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      status: "unknown",
    };
  } catch (error) {
    return {
      subject: "",
      issuer: "",
      serialNumber: "",
      validFrom: "",
      validUntil: "",
      status: "unknown",
      error: `Failed to parse certificate: ${error}`,
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
export function formatCertificateInfo(certPem: string, certType: string = "Certificate"): string {
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

  if (info.subjectAlternativeNames && info.subjectAlternativeNames.length > 0) {
    lines.push(`Subject Alternative Names: ${info.subjectAlternativeNames.join(", ")}`);
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

  if (info.logicalHosts && info.logicalHosts.length > 0) {
    lines.push(`Logical Hosts: ${info.logicalHosts.join(", ")}`);
  }

  // Add validity status
  if (info.status === "valid" && info.daysRemaining !== undefined) {
    if (info.daysRemaining > 0) {
      lines.push(`Status: Valid (${info.daysRemaining} days remaining)`);
    } else if (info.hoursRemaining !== undefined && info.hoursRemaining > 0) {
      if (info.minutesRemaining !== undefined && info.minutesRemaining > 0) {
        lines.push(
          `Status: Valid (${info.hoursRemaining} hours, ${info.minutesRemaining} minutes remaining)`
        );
      } else {
        lines.push(`Status: Valid (${info.hoursRemaining} hours remaining)`);
      }
    } else if (info.minutesRemaining !== undefined) {
      lines.push(`Status: Valid (${info.minutesRemaining} minutes remaining)`);
    }
  } else if (info.status === "expired") {
    lines.push("Status: Expired");
  } else if (info.status === "not_yet_valid") {
    lines.push("Status: Not yet valid");
  }

  return lines.join("\n");
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
  constructor(connectionGrant: HttpConnectionGrant, timeoutSeconds: number = 30.0) {
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
    logicals?: string[]
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
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutSeconds * 1000);

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
          const certificateChainPem: string = result.certificate_chain_pem || certificatePem;

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
            const chainCerts = certificateChainPem.split("-----END CERTIFICATE-----\n").slice(0, -1);

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
            const errorData = await response.json();
            errorDetail = errorData.detail || errorDetail;
          } catch {
            errorDetail = await response.text();
          }

          logger.error("certificate_request_failed", {
            requester_id: requesterId,
            status_code: response.status,
            error: errorDetail,
          });

          throw new CertificateRequestError(
            `Certificate request failed (HTTP ${response.status}): ${errorDetail}`
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
          `Certificate request timed out after ${this.timeoutSeconds} seconds`
        );
      }

      logger.error("certificate_request_network_error", {
        requester_id: requesterId,
        error: String(error),
      });
      throw new CertificateRequestError(`Network error requesting certificate: ${error}`);
    }
  }
}
