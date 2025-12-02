import { describe, it, expect, beforeEach, vi } from "vitest";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const loggerMock = {
  debug: vi.fn(),
  warning: vi.fn(),
  error: vi.fn(),
};

const validateMock = vi.fn(() => ({ isValid: true }));

vi.mock("@naylence/core", () => {
  const SigningMaterial = {
    X509_CHAIN: "X509_CHAIN",
    JWK: "JWK",
  } as const;

  return {
    SigningMaterial,
  };
});

vi.mock("@naylence/runtime", () => {
  class SigningConfigClass {
    public signingMaterial: string;

    public constructor(options: { signingMaterial?: string } = {}) {
      this.signingMaterial = options.signingMaterial ?? "JWK";
    }
  }

  return {
    SigningConfigClass,
    AuthInjectionStrategyFactory: {
      createAuthInjectionStrategy: vi.fn(async () => ({
        apply: vi.fn(),
        cleanup: vi.fn(),
      })),
    },
    getLogger: vi.fn(() => loggerMock),
  };
});

vi.mock("../src/naylence/fame/security/cert/ca-service-client.js", () => ({
  CAServiceClient: class {
    public constructor(_: unknown) {}
    public async requestCertificate(): Promise<never> {
      throw new Error("not implemented in tests");
    }
  },
}));

vi.mock("../src/naylence/fame/security/cert/ca-types.js", () => ({
  CertificateRequestError: class extends Error {},
}));

vi.mock("../src/naylence/fame/security/cert/grants.js", () => ({
  GRANT_PURPOSE_CA_SIGN: "ca-sign",
}));

vi.mock("../src/naylence/fame/security/cert/util.js", () => ({
  validateJwkX5cCertificate: validateMock,
}));

vi.mock("../src/naylence/fame/security/cert/node-ed25519-csr.js", () => ({
  createEd25519CsrFromPem: vi.fn(async () => ({ csrPem: "stub-csr" })),
}));

const { default: DefaultCertificateManager } = await import(
  "../src/naylence/fame/security/cert/default-certificate-manager.js"
);

const { SigningMaterial } = await import("@naylence/core");
const { SigningConfigClass } = await import("@naylence/runtime");

const SAMPLE_CERT = [
  "-----BEGIN CERTIFICATE-----",
  "MIIBstubcertificate==",
  "-----END CERTIFICATE-----",
].join("\n");

const SAMPLE_CHAIN = [
  "-----BEGIN CERTIFICATE-----",
  "MIIBstubchain==",
  "-----END CERTIFICATE-----",
].join("\n");

const SAMPLE_TRUST = [
  "-----BEGIN CERTIFICATE-----",
  "MIIBtrustanchor==",
  "-----END CERTIFICATE-----",
].join("\n");

type StoredMaterial = {
  certificatePem: string;
  certificateChainPem: string | null;
};

describe("DefaultCertificateManager environment support", () => {
  beforeEach(() => {
    loggerMock.debug.mockClear();
    loggerMock.warning.mockClear();
    loggerMock.error.mockClear();
    validateMock.mockClear();
  });

  it("uses injected PEM sources when process.env is unavailable (browser-like)", async () => {
    const originalEnv = process.env;
    (process as unknown as { env?: NodeJS.ProcessEnv | undefined }).env =
      undefined;

    const providerState: { material: StoredMaterial | null } = {
      material: null,
    };

    const provider = {
      nodeJwk: () =>
        providerState.material
          ? { x5c: [providerState.material.certificatePem] }
          : null,
    };

    const persistHook = vi.fn(async (material: StoredMaterial) => {
      providerState.material = material;
    });

    const manager = new DefaultCertificateManager({
      cryptoProvider: provider,
      certificateMaterial: async () => ({
        certificatePem: SAMPLE_CERT,
        certificateChainPem: SAMPLE_CHAIN,
      }),
      trustStorePem: SAMPLE_TRUST,
      persistCertificateMaterial: persistHook,
    });
    manager.setSigning(
      new SigningConfigClass({ signingMaterial: SigningMaterial.X509_CHAIN }),
    );

    const browserInternals = manager as unknown as Record<string, unknown>;
    expect(typeof browserInternals.certificatePersistenceHook).toBe("function");

    try {
      const welcomeFrame = {
        security_settings: { signing_material: SigningMaterial.X509_CHAIN },
        systemId: "node-browser",
        assignedPath: "/nodes/browser",
        acceptedLogicals: ["alpha", "beta"],
      };

  const result = await manager.ensureCertificate(welcomeFrame as never);

      expect(result).toBe(true);
      expect(providerState.material).toEqual({
        certificatePem: SAMPLE_CERT,
        certificateChainPem: SAMPLE_CHAIN,
      });
      expect(persistHook).toHaveBeenCalledTimes(1);
      expect(validateMock).toHaveBeenCalledWith(
        expect.objectContaining({ trustStorePem: SAMPLE_TRUST }),
      );
    } finally {
      (process as unknown as { env?: NodeJS.ProcessEnv }).env = originalEnv;
    }
  });

  it("falls back to Node environment variables and files", async () => {
    const tmpDir = await fs.mkdtemp(join(tmpdir(), "naylence-cert-test-"));
    const certPath = join(tmpDir, "node-cert.pem");
    const chainPath = join(tmpDir, "node-chain.pem");
    const trustPath = join(tmpDir, "trust.pem");

    await fs.writeFile(certPath, `${SAMPLE_CERT}\n`, "utf8");
    await fs.writeFile(chainPath, `${SAMPLE_CHAIN}\n`, "utf8");
    await fs.writeFile(trustPath, `${SAMPLE_TRUST}\n`, "utf8");

    const originalCertFile = process.env.FAME_NODE_CERT_FILE;
    const originalChainFile = process.env.FAME_NODE_CERT_CHAIN_FILE;
    const originalTrust = process.env.FAME_CA_CERTS;
    process.env.FAME_NODE_CERT_FILE = certPath;
    process.env.FAME_NODE_CERT_CHAIN_FILE = chainPath;
    process.env.FAME_CA_CERTS = trustPath;

    const providerState: { material: StoredMaterial | null } = {
      material: null,
    };

    const storeSignedCertificate = vi.fn(
      (certificatePem: string, certificateChainPem?: string | null) => {
        providerState.material = {
          certificatePem,
          certificateChainPem: certificateChainPem ?? null,
        };
      },
    );

    const provider = {
      hasCertificate: () => Boolean(providerState.material),
      storeSignedCertificate,
      nodeJwk: () =>
        providerState.material
          ? { x5c: [providerState.material.certificatePem] }
          : null,
    };

    const manager = new DefaultCertificateManager({
      cryptoProvider: provider,
    });
    manager.setSigning(
      new SigningConfigClass({ signingMaterial: SigningMaterial.X509_CHAIN }),
    );

    const nodeInternals = manager as unknown as Record<string, unknown>;
    expect(nodeInternals.certificatePersistenceHook).toBeNull();

    try {
      const welcomeFrame = {
        security_settings: { signing_material: SigningMaterial.X509_CHAIN },
        systemId: "node-runtime",
        assignedPath: "/nodes/runtime",
        acceptedLogicals: ["alpha"],
      };

  const result = await manager.ensureCertificate(welcomeFrame as never);

      expect(result).toBe(true);
      expect(providerState.material).toEqual({
        certificatePem: SAMPLE_CERT,
        certificateChainPem: SAMPLE_CHAIN,
      });
      expect(storeSignedCertificate).toHaveBeenCalledTimes(1);
      expect(validateMock).toHaveBeenCalledWith(
        expect.objectContaining({ trustStorePem: SAMPLE_TRUST }),
      );
    } finally {
      if (originalCertFile === undefined) {
        delete process.env.FAME_NODE_CERT_FILE;
      } else {
        process.env.FAME_NODE_CERT_FILE = originalCertFile;
      }

      if (originalChainFile === undefined) {
        delete process.env.FAME_NODE_CERT_CHAIN_FILE;
      } else {
        process.env.FAME_NODE_CERT_CHAIN_FILE = originalChainFile;
      }

      if (originalTrust === undefined) {
        delete process.env.FAME_CA_CERTS;
      } else {
        process.env.FAME_CA_CERTS = originalTrust;
      }

      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});