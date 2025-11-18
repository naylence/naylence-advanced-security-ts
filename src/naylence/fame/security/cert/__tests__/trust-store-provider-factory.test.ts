import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { SigningMaterial, type FameEnvelope } from "@naylence/core";
import {
  SigningConfigClass,
  type KeyProvider,
  secureDigest,
} from "@naylence/runtime";
import { canonicalJson } from "@naylence/runtime/naylence/fame/security/signing/eddsa-signer-verifier.js";

import type { TrustStoreProvider } from "../../cert/trust-store/trust-store-provider.js";
import { EdDSAEnvelopeVerifier } from "../../signing/eddsa-envelope-verifier.js";
import { AdvancedEdDSAEnvelopeVerifierFactory } from "../../signing/eddsa-envelope-verifier-factory.js";
import { TrustStoreProviderFactory } from "../../cert/trust-store/trust-store-provider-factory.js";

const SAMPLE_PEM = `-----BEGIN CERTIFICATE-----
MIIBnzCCAUGgAwIBAgIJAL0fakepemMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM
CHRlc3Qgcm9vdDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBMxET
APBgNVBAMMCHRlc3Qgcm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIXe
jVT0fakepemFTtcDM0ust0nqAnpgho6n5E04nCZIWKU9E8MydTg3PjQ7sjrb9F
2CahkYMJDOgAwEBAAGjUzBRMB0GA1UdDgQWBBRfakepemLhDGsv1oY4Y4vW8pZ
IOfAfBgNVHSMEGDAWgBRfakepemLhDGsv1oY4Y4vW8pZIOFAPBgNVHRMBAf8EB
TADAQH/MAoGCCqGSM49BAMCA0cAMEQCIGfakepem2ZGwlZsuZ4SB3n3Pp5Pt8n
/zA+WVcxxt0SAiBNfakepemIq1TANnp6MHQ6OruwcB2V2AMXnFYYoPOPQxQ==
-----END CERTIFICATE-----
`;

const SAMPLE_X5C = SAMPLE_PEM.replace(/-----BEGIN CERTIFICATE-----/g, "")
  .replace(/-----END CERTIFICATE-----/g, "")
  .replace(/\s+/g, "");

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

describe("EnvTrustStoreProviderFactory", () => {
  let originalValue: string | undefined;

  beforeEach(() => {
    originalValue = process.env.FAME_CA_CERTS;
  });

  afterEach(() => {
    if (originalValue === undefined) {
      delete process.env.FAME_CA_CERTS;
    } else {
      process.env.FAME_CA_CERTS = originalValue;
    }
  });

  it("returns PEM from inline environment configuration", async () => {
    process.env.FAME_CA_CERTS = SAMPLE_PEM;
    const { EnvTrustStoreProviderFactory } = await import(
      "../../cert/trust-store/node-trust-store-provider-factory.js"
    );

    const factory = new EnvTrustStoreProviderFactory();
    const provider = await factory.create();

    const pem = await provider.getTrustStorePem();
    expect(pem).toContain("-----BEGIN CERTIFICATE-----");
    const roots = await provider.getRoots();
    expect(roots).toHaveLength(1);
  });

  it("returns an informative placeholder when configuration is missing", async () => {
    delete process.env.FAME_CA_CERTS;
    const { EnvTrustStoreProviderFactory } = await import(
      "../../cert/trust-store/node-trust-store-provider-factory.js"
    );

    const factory = new EnvTrustStoreProviderFactory();
    const provider = await factory.create();
    await expect(provider.getTrustStorePem()).rejects.toThrow("Trust store is not configured");
    const roots = await provider.getRoots();
    expect(Array.from(roots)).toHaveLength(0);
  });
});

describe("BrowserTrustStoreProviderFactory", () => {
  const originalFetch = globalThis.fetch;
  let originalDisableCache: string | undefined;

  beforeEach(() => {
    originalDisableCache = process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE;
    process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE = "true";
  });

  afterEach(async () => {
    if (originalFetch) {
      globalThis.fetch = originalFetch;
    } else {
      delete (globalThis as { fetch?: typeof fetch }).fetch;
    }

    if (originalDisableCache === undefined) {
      delete process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE;
    } else {
      process.env.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE = originalDisableCache;
    }

    jest.resetModules();
  });

  it("fetches PEM bundles once and caches the result", async () => {
    jest.resetModules();

    const fsMock = {
      readFile: jest.fn(async () => {
        const error = new Error("not found") as NodeJS.ErrnoException;
        error.code = "ENOENT";
        throw error;
      }),
      writeFile: jest.fn(async () => undefined),
      mkdir: jest.fn(async () => undefined),
    } as const;

    const pathMock = {
      join: (...parts: string[]) => parts.join("/"),
    } as const;

    const osMock = {
      homedir: () => "/tmp/naylence-trust-store-test",
    } as const;

    await jest.unstable_mockModule("node:fs/promises", () => ({
      default: fsMock,
      readFile: fsMock.readFile,
      writeFile: fsMock.writeFile,
      mkdir: fsMock.mkdir,
    }));

    await jest.unstable_mockModule("node:path", () => ({
      default: pathMock,
      join: pathMock.join,
    }));

    await jest.unstable_mockModule("node:os", () => ({
      default: osMock,
      homedir: osMock.homedir,
    }));

    const response = new Response(SAMPLE_PEM, {
      status: 200,
      headers: { "Content-Type": "application/pem-certificate-chain" },
    });
    const fetchMock = jest.fn(async () => response);
    (globalThis as { fetch?: typeof fetch }).fetch = fetchMock as unknown as typeof fetch;

    const module = await import(
      "../../cert/trust-store/browser-trust-store-provider-factory.js"
    );
    const { BrowserTrustStoreProviderFactory } = module;

    const factory = new BrowserTrustStoreProviderFactory();
    const provider = await factory.create({
      type: "BrowserTrustStoreProvider",
      url: "https://example.com/trust.pem",
      allowTofu: true,
      enforcePinsInBrowser: false,
    });

    const first = await provider.getTrustStorePem();
    const second = await provider.getTrustStorePem();

    expect(first).toContain("-----BEGIN CERTIFICATE-----");
    expect(second).toBe(first);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("AdvancedEdDSAEnvelopeVerifierFactory", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("resolves a trust store provider when none is supplied", async () => {
    const stubProvider: TrustStoreProvider = {
      getRoots: jest.fn(async () => []),
      getTrustStorePem: jest.fn(async () => SAMPLE_PEM),
    };

    const createSpy = jest
      .spyOn(TrustStoreProviderFactory, "createTrustStoreProvider")
      .mockResolvedValue(stubProvider);

    const keyProvider: KeyProvider = {
      getKey: jest.fn(async () => ({
        kid: "kid-1",
        sid: "sid-1",
        use: "sig",
        kty: "OKP",
        crv: "Ed25519",
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      })),
      getKeysForPath: jest.fn(async () => []),
    };

    const factory = new AdvancedEdDSAEnvelopeVerifierFactory();
    await factory.create(null, keyProvider, null);

    expect(createSpy).toHaveBeenCalledTimes(1);
  });
});

describe("EdDSAEnvelopeVerifier", () => {
  it("requests trust store material when verifying certificate-backed keys", async () => {
    const trustStoreProvider: TrustStoreProvider = {
      getRoots: jest.fn(async () => [{ pem: SAMPLE_PEM }]),
      getTrustStorePem: jest.fn(async () => SAMPLE_PEM),
    };

    const keyProvider: KeyProvider = {
      getKey: jest.fn(async () => ({
        kid: "kid-1",
        sid: "sid-1",
        use: "sig",
        kty: "OKP",
        crv: "Ed25519",
        x5c: [SAMPLE_X5C],
      })),
      getKeysForPath: jest.fn(async () => []),
    };

    const verifier = new EdDSAEnvelopeVerifier(keyProvider, {
      signingConfig: new SigningConfigClass({
        signingMaterial: SigningMaterial.X509_CHAIN,
      }),
      trustStoreProvider,
    });

    const payload = { value: "hello" };
    const payloadDigest = secureDigest(canonicalJson(payload));

    const signatureBytes = new Uint8Array(64);
    signatureBytes.fill(1);

    const envelope = {
      version: "1",
      id: "env-1",
      sid: "sid-1",
      frame: {
        type: "Data",
        payload,
        pd: payloadDigest,
      },
      sec: {
        sig: {
          kid: "kid-1",
          sid: "sid-1",
          alg: "EdDSA",
          val: toBase64Url(signatureBytes),
        },
      },
    } as unknown as FameEnvelope;

    await expect(verifier.verifyEnvelope(envelope)).rejects.toThrow(
      "Failed to parse certificate at index 0",
    );

    expect(trustStoreProvider.getTrustStorePem).toHaveBeenCalled();
  });
});
