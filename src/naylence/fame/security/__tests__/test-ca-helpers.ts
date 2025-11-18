/**
 * Test helpers for CA certificate provisioning in tests.
 *
 * Provides utilities for setting up test Certificate Authority (CA)
 * infrastructure for integration tests that require X.509 certificates.
 */

import type { AddressInfo } from "node:net";
import { createApp } from "../cert/ca-server.js";
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

  /** Base URL for the running CA service */
  caServiceUrl: string;

  /** Cleanup function to stop the CA service and restore environment */
  cleanup: () => Promise<void>;
}

/**
 * Create test CA credentials and set up environment.
 *
 * Generates a test root CA, starts an in-process CA HTTP service, and configures
 * environment variables so runtime components can request certificates during tests.
 *
 * NOTE: The generated CA and credentials are suitable for automated tests only and
 * must never be used in production deployments.
 *
 * @returns Test CA credentials with cleanup function
 */
export async function setupTestCACredentials(): Promise<TestCACredentials> {
  const [rootCertPem, rootKeyPem, rootPublicKeyPem] = await createTestCA();

  const previousEnv = {
    FAME_CA_CERT_PEM: process.env.FAME_CA_CERT_PEM,
    FAME_CA_KEY_PEM: process.env.FAME_CA_KEY_PEM,
    FAME_CA_CERTS: process.env.FAME_CA_CERTS,
    FAME_CA_SERVICE_URL: process.env.FAME_CA_SERVICE_URL,
    NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE:
      process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE,
  } as const;

  process.env.FAME_CA_CERT_PEM = rootCertPem;
  process.env.FAME_CA_KEY_PEM = rootKeyPem;
  process.env.FAME_CA_CERTS = JSON.stringify([rootCertPem]);
  process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE = "true";

  const { app } = await createApp();
  const host = "127.0.0.1";
  await app.listen({ host, port: 0 });

  const address = app.server.address();
  if (!address) {
    await app.close();
    throw new Error("Failed to determine CA service address");
  }

  let resolvedHost: string;
  let resolvedPort: number;

  if (typeof address === "string") {
    const url = new URL(address.startsWith("http") ? address : `http://${address}`);
    resolvedHost = url.hostname || host;
    resolvedPort = Number.parseInt(url.port, 10);
  } else {
    const nodeAddress = address as AddressInfo;
    resolvedPort = nodeAddress.port;
    if (!Number.isFinite(resolvedPort)) {
      await app.close();
      throw new Error("CA service returned invalid port");
    }
    if (nodeAddress.family === "IPv6" && (!nodeAddress.address || nodeAddress.address === "::")) {
      resolvedHost = host;
    } else if (!nodeAddress.address || nodeAddress.address === "0.0.0.0") {
      resolvedHost = host;
    } else {
      resolvedHost = nodeAddress.address;
    }
  }

  const caServiceUrl = `http://${resolvedHost}:${resolvedPort}/fame/v1/ca`;
  process.env.FAME_CA_SERVICE_URL = caServiceUrl;

  const cleanup = async (): Promise<void> => {
    try {
      await app.close();
    } finally {
      restoreEnv("FAME_CA_CERT_PEM", previousEnv.FAME_CA_CERT_PEM);
      restoreEnv("FAME_CA_KEY_PEM", previousEnv.FAME_CA_KEY_PEM);
      restoreEnv("FAME_CA_CERTS", previousEnv.FAME_CA_CERTS);
      restoreEnv("FAME_CA_SERVICE_URL", previousEnv.FAME_CA_SERVICE_URL);
      restoreEnv(
        "NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE",
        previousEnv.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE,
      );
    }
  };

  return {
    rootCertPem,
    rootKeyPem,
    rootPublicKeyPem,
    caServiceUrl,
    cleanup,
  };
}

function restoreEnv(key: string, value: string | undefined): void {
  if (typeof value === "string") {
    process.env[key] = value;
    return;
  }
  delete process.env[key];
}
