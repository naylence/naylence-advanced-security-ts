/**
 * Test helpers for CA certificate provisioning in tests.
 *
 * Provides utilities for setting up test Certificate Authority (CA)
 * infrastructure for integration tests that require X.509 certificates.
 */

import { createTestCA } from "../cert/internal-ca-service.js";

/**
 * Test CA credentials.
 */
export interface TestCACredentials {
  /** Root CA certificate PEM */
  rootCertPem: string;

  /** Root CA private key PEM */
  rootKeyPem: string;

  /** Root CA public key PEM */
  rootPublicKeyPem: string;

  /** Cleanup function to remove environment variables */
  cleanup: () => void;
}

/**
 * Create test CA credentials and set up environment.
 *
 * Generates a test root CA and configures environment variables for certificate-based
 * signing during tests. For now, this uses the root CA certificate as the node certificate
 * until the full CA signing implementation is complete.
 *
 * NOTE: This is a temporary workaround - in production, nodes should request proper
 * certificates from the CA service with appropriate SANs and usage constraints.
 *
 * @returns Test CA credentials with cleanup function
 */
export async function setupTestCACredentials(): Promise<TestCACredentials> {
  // Generate test root CA
  const [rootCertPem, rootKeyPem, rootPublicKeyPem] = await createTestCA();

  // TEMPORARY WORKAROUND: Use the root CA cert as node cert
  // This is valid PEM and allows the test to proceed without full CA signing implementation
  // The crypto provider will be created with the root CA key pair for signing
  // TODO: Implement proper certificate signing in CASigningService.issueCertificate()
  // and generate node-specific certificates with proper SANs
  process.env.FAME_NODE_CERT_PEM = rootCertPem;
  process.env.FAME_CA_CERT_PEM = rootCertPem;

  // Cleanup function
  const cleanup = (): void => {
    delete process.env.FAME_NODE_CERT_PEM;
    delete process.env.FAME_CA_CERT_PEM;
    delete process.env.FAME_CA_SERVICE_URL;
  };

  return {
    rootCertPem,
    rootKeyPem,
    rootPublicKeyPem,
    cleanup,
  };
}

