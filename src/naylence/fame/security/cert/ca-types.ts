/**
 * Certificate Authority (CA) types and interfaces.
 *
 * Provides type definitions for CA service operations, certificate signing requests,
 * and certificate issuance responses.
 */

/**
 * Authorizer interface placeholder (from runtime package).
 * TODO: Import from naylence-runtime-ts once dependency is established.
 */
export interface Authorizer {
  // Placeholder interface
}

/**
 * Certificate Signing Request payload.
 */
export interface CertificateSigningRequest {
  /** Certificate Signing Request in PEM format */
  csrPem: string;

  /** ID of the node requesting the certificate */
  requesterId: string;

  /** Physical path for the node (optional) */
  physicalPath?: string;

  /** Host-like logical addresses the node will serve */
  logicals?: string[];
}

/**
 * Certificate issuance response.
 */
export interface CertificateIssuanceResponse {
  /** Issued certificate in PEM format */
  certificatePem: string;

  /** Full certificate chain in PEM format (optional) */
  certificateChainPem?: string;

  /** Certificate expiration time in ISO format */
  expiresAt: string;
}

/**
 * Abstract CA signing service interface.
 *
 * Defines the contract for certificate authority services that can issue
 * certificates from certificate signing requests.
 */
export abstract class CAService {
  /**
   * Optional authorizer for request authentication.
   */
  get authorizer(): Authorizer | null {
    return null;
  }

  /**
   * Issue a certificate from a CSR.
   *
   * @param csr - Certificate signing request
   * @returns Certificate issuance response with the signed certificate
   */
  abstract issueCertificate(
    csr: CertificateSigningRequest,
  ): Promise<CertificateIssuanceResponse>;
}

/**
 * Error thrown when a certificate request fails.
 */
export class CertificateRequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CertificateRequestError";
    Object.setPrototypeOf(this, CertificateRequestError.prototype);
  }
}

/**
 * Certificate information extracted from a certificate.
 */
export interface CertificateInfo {
  /** Subject DN */
  subject: string;

  /** Issuer DN */
  issuer: string;

  /** Serial number (hex format) */
  serialNumber: string;

  /** Valid from timestamp */
  validFrom: string;

  /** Valid until timestamp */
  validUntil: string;

  /** Subject Alternative Names */
  subjectAlternativeNames?: string[];

  /** Certificate validity status */
  status: "valid" | "expired" | "not_yet_valid" | "unknown";

  /** Days remaining if valid */
  daysRemaining?: number;

  /** Hours remaining if valid */
  hoursRemaining?: number;

  /** Minutes remaining if valid */
  minutesRemaining?: number;

  /** SPIFFE ID (if present) */
  spiffeId?: string;

  /** Node SID (if present - Fame extension) */
  nodeSid?: string;

  /** Node ID (if present - Fame extension) */
  nodeId?: string;

  /** Logical hosts (if present - Fame extension) */
  logicalHosts?: string[];

  /** Error message if parsing failed */
  error?: string;
}
