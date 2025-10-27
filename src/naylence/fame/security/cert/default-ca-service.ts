/**
 * Default CA service implementation with environment variable support.
 *
 * Wraps InternalCAService (CASigningService) with automatic credential
 * loading from environment variables and test CA fallback.
 */

import type {
  Authorizer,
  CertificateIssuanceResponse,
  CertificateSigningRequest,
} from "./ca-types.js";
import { CAService } from "./ca-types.js";
import { CASigningService, createTestCA } from "./internal-ca-service.js";

/**
 * Environment variable names for CA credentials.
 */
export const ENV_FAME_CA_CERT_FILE = "FAME_CA_CERT_FILE";
export const ENV_FAME_CA_CERT_PEM = "FAME_CA_CERT_PEM";
export const ENV_FAME_CA_KEY_FILE = "FAME_CA_KEY_FILE";
export const ENV_FAME_CA_KEY_PEM = "FAME_CA_KEY_PEM";
export const ENV_FAME_INTERMEDIATE_CHAIN_FILE = "FAME_INTERMEDIATE_CHAIN_FILE";
export const ENV_FAME_INTERMEDIATE_CHAIN_PEM = "FAME_INTERMEDIATE_CHAIN_PEM";
export const ENV_FAME_SIGNING_CERT_FILE = "FAME_SIGNING_CERT_FILE";
export const ENV_FAME_SIGNING_CERT_PEM = "FAME_SIGNING_CERT_PEM";
export const ENV_FAME_SIGNING_KEY_FILE = "FAME_SIGNING_KEY_FILE";
export const ENV_FAME_SIGNING_KEY_PEM = "FAME_SIGNING_KEY_PEM";

/**
 * Options for DefaultCAService.
 */
export interface DefaultCAServiceOptions {
  /** Root CA certificate in PEM format */
  caCertPem?: string;

  /** Root CA private key in PEM format */
  caKeyPem?: string;

  /** Complete intermediate CA chain in PEM format (optional) */
  intermediateChainPem?: string;

  /** Certificate to use for signing (leaf of the chain, optional) */
  signingCertPem?: string;

  /** Private key for the signing certificate (optional) */
  signingKeyPem?: string;

  /** Authorizer for access control (optional) */
  authorizer?: Authorizer;
}

/**
 * CA credentials loaded from configuration or environment.
 */
interface CACredentials {
  rootCaCertPem: string;
  rootCaKeyPem: string;
  intermediateChainPem?: string;
  signingCertPem?: string;
  signingKeyPem?: string;
}

/**
 * Default CA service with environment variable support and test CA fallback.
 *
 * Provides automatic credential loading from:
 * 1. Constructor options
 * 2. Environment variables (FAME_CA_CERT_PEM, FAME_CA_KEY_PEM, etc.)
 * 3. Test CA generation (development only)
 */
export class DefaultCAService extends CAService {
  private readonly caCertPem?: string;
  private readonly caKeyPem?: string;
  private readonly intermediateChainPem?: string;
  private readonly signingCertPem?: string;
  private readonly signingKeyPem?: string;
  private readonly authorizerInstance?: Authorizer;

  constructor(options: DefaultCAServiceOptions = {}) {
    super();

    this.caCertPem = options.caCertPem;
    this.caKeyPem = options.caKeyPem;
    this.intermediateChainPem = options.intermediateChainPem;
    this.signingCertPem = options.signingCertPem;
    this.signingKeyPem = options.signingKeyPem;
    this.authorizerInstance = options.authorizer;
  }

  get authorizer(): Authorizer | null {
    return this.authorizerInstance ?? null;
  }

  /**
   * Get CA credentials from environment or configuration.
   *
   * @returns CA credentials loaded from config or environment
   */
  private async getCACredentials(): Promise<CACredentials> {
    let caCertPem = this.caCertPem;
    let caKeyPem = this.caKeyPem;
    let intermediateChainPem = this.intermediateChainPem;
    let signingCertPem = this.signingCertPem;
    let signingKeyPem = this.signingKeyPem;

    // Try environment variables if not provided
    if (!caCertPem) {
      const caCertFile = process.env[ENV_FAME_CA_CERT_FILE];
      if (caCertFile) {
        caCertPem = await this.readFileIfExists(caCertFile);
      }
      if (!caCertPem) {
        caCertPem = process.env[ENV_FAME_CA_CERT_PEM];
      }
    }

    if (!caKeyPem) {
      const caKeyFile = process.env[ENV_FAME_CA_KEY_FILE];
      if (caKeyFile) {
        caKeyPem = await this.readFileIfExists(caKeyFile);
      }
      if (!caKeyPem) {
        caKeyPem = process.env[ENV_FAME_CA_KEY_PEM];
      }
    }

    // Load intermediate chain
    if (!intermediateChainPem) {
      const intermediateChainFile =
        process.env[ENV_FAME_INTERMEDIATE_CHAIN_FILE];
      if (intermediateChainFile) {
        intermediateChainPem = await this.readFileIfExists(
          intermediateChainFile,
        );
      }
      if (!intermediateChainPem) {
        intermediateChainPem = process.env[ENV_FAME_INTERMEDIATE_CHAIN_PEM];
      }
    }

    // Load signing certificate
    if (!signingCertPem) {
      const signingCertFile = process.env[ENV_FAME_SIGNING_CERT_FILE];
      if (signingCertFile) {
        signingCertPem = await this.readFileIfExists(signingCertFile);
      }
      if (!signingCertPem) {
        signingCertPem = process.env[ENV_FAME_SIGNING_CERT_PEM];
      }
    }

    // Load signing key
    if (!signingKeyPem) {
      const signingKeyFile = process.env[ENV_FAME_SIGNING_KEY_FILE];
      if (signingKeyFile) {
        signingKeyPem = await this.readFileIfExists(signingKeyFile);
      }
      if (!signingKeyPem) {
        signingKeyPem = process.env[ENV_FAME_SIGNING_KEY_PEM];
      }
    }

    // Fallback to test CA if nothing configured
    if (!caCertPem || !caKeyPem) {
      console.warn(
        "No CA credentials configured, using test CA (not for production!)",
      );
      const [rootCert, rootKey] = await createTestCA();
      return {
        rootCaCertPem: rootCert,
        rootCaKeyPem: rootKey,
        intermediateChainPem,
        signingCertPem,
        signingKeyPem,
      };
    }

    return {
      rootCaCertPem: caCertPem,
      rootCaKeyPem: caKeyPem,
      intermediateChainPem,
      signingCertPem,
      signingKeyPem,
    };
  }

  /**
   * Read file contents if the file exists.
   *
   * @param filePath - Path to the file
   * @returns File contents or undefined if file doesn't exist
   */
  private async readFileIfExists(
    filePath: string,
  ): Promise<string | undefined> {
    // Browser environment - files not supported
    if (typeof require === "undefined" && typeof window !== "undefined") {
      return undefined;
    }

    // Node.js environment
    try {
      const fs = await import("fs/promises");
      const stats = await fs.stat(filePath);
      if (stats.isFile()) {
        return await fs.readFile(filePath, "utf-8");
      }
    } catch {
      // File doesn't exist or can't be read
    }

    return undefined;
  }

  /**
   * Parse a PEM certificate chain into individual certificates.
   *
   * @param chainPem - Certificate chain in PEM format
   * @returns List of individual certificate PEM strings, ordered from leaf to root
   */
  private parseCertificateChain(chainPem: string): string[] {
    const certificates: string[] = [];
    let currentCert = "";
    let inCert = false;

    for (const line of chainPem.split("\n")) {
      if (line.includes("-----BEGIN CERTIFICATE-----")) {
        inCert = true;
        currentCert = line + "\n";
      } else if (line.includes("-----END CERTIFICATE-----")) {
        currentCert += line + "\n";
        certificates.push(currentCert.trim());
        currentCert = "";
        inCert = false;
      } else if (inCert) {
        currentCert += line + "\n";
      }
    }

    return certificates;
  }

  /**
   * Issue a certificate from a CSR using the local CA service.
   *
   * @param csr - Certificate signing request
   * @returns Certificate issuance response with the signed certificate
   */
  async issueCertificate(
    csr: CertificateSigningRequest,
  ): Promise<CertificateIssuanceResponse> {
    // Get CA credentials including intermediate chain
    const credentials = await this.getCACredentials();

    // Determine which certificate and key to use for signing
    let signingService: CASigningService;

    if (credentials.signingCertPem && credentials.signingKeyPem) {
      // Use specific signing certificate (leaf of intermediate chain)
      signingService = new CASigningService({
        rootCertPem: credentials.signingCertPem,
        rootKeyPem: credentials.signingKeyPem,
      });
      console.debug("Using signing certificate for signing:", csr.requesterId);
    } else if (credentials.intermediateChainPem) {
      // Extract the leaf certificate from the intermediate chain
      const intermediateCerts = this.parseCertificateChain(
        credentials.intermediateChainPem,
      );
      if (intermediateCerts.length > 0 && credentials.signingKeyPem) {
        // Use the first certificate in the chain (should be the leaf/signing certificate)
        const leafCertPem = intermediateCerts[0];
        signingService = new CASigningService({
          rootCertPem: leafCertPem!,
          rootKeyPem: credentials.signingKeyPem,
        });
        console.debug(
          "Using intermediate leaf CA for signing:",
          csr.requesterId,
        );
      } else {
        // Fall back to root CA if no signing key provided
        signingService = new CASigningService({
          rootCertPem: credentials.rootCaCertPem,
          rootKeyPem: credentials.rootCaKeyPem,
        });
        console.warn(
          "No signing key for intermediate, falling back to root:",
          csr.requesterId,
        );
      }
    } else {
      // Sign with root CA
      signingService = new CASigningService({
        rootCertPem: credentials.rootCaCertPem,
        rootKeyPem: credentials.rootCaKeyPem,
      });
      console.debug("Using root CA for signing:", csr.requesterId);
    }

    // Issue the certificate using the configured signing service
    try {
      const { certificatePem, expiresAt } =
        await signingService.issueCertificate(csr);

      const chainParts: string[] = [certificatePem.trim()];
      const rootCertPem = credentials.rootCaCertPem?.trim();
      const signingCertPem = credentials.signingCertPem?.trim();

      const normalizeCert = (pem: string | undefined): string | undefined =>
        pem?.trim();

      if (credentials.intermediateChainPem) {
        const intermediateCerts = this.parseCertificateChain(
          credentials.intermediateChainPem,
        );

        for (const certPem of intermediateCerts) {
          const normalized = normalizeCert(certPem);
          if (!normalized) {
            continue;
          }

          if (normalized === chainParts[0]) {
            continue;
          }

          if (rootCertPem && normalized === rootCertPem) {
            continue;
          }

          chainParts.push(normalized);
        }
      } else if (signingCertPem && signingCertPem !== rootCertPem) {
        if (signingCertPem !== chainParts[0]) {
          chainParts.push(signingCertPem);
        }
      }

      const certificateChainPem = chainParts.join("\n");

      return {
        certificatePem,
        certificateChainPem,
        expiresAt,
      };
    } catch (error) {
      console.error("Certificate issuance failed:", csr.requesterId, error);
      throw error;
    }
  }
}
