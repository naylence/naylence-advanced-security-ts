import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";

type MockedFs = {
  readFile: jest.MockedFunction<(...args: unknown[]) => Promise<string>>;
  writeFile: jest.MockedFunction<(...args: unknown[]) => Promise<void>>;
  mkdir: jest.MockedFunction<(...args: unknown[]) => Promise<void>>;
};

type MockedPath = {
  join: (...parts: string[]) => string;
};

type MockedOs = {
  homedir: () => string;
};

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

async function setupModule(fetchOverride?: typeof fetch) {
  const fsMock: MockedFs = {
    readFile: jest.fn() as MockedFs["readFile"],
    writeFile: jest.fn() as MockedFs["writeFile"],
    mkdir: jest.fn() as MockedFs["mkdir"],
  };

  const pathMock: MockedPath = {
    join: (...parts: string[]) => parts.join("/"),
  };

  const osMock: MockedOs = {
    homedir: () => "/tmp/naylence-http-trust-bundles",
  };

  const loggerMock = {
    debug: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
  };

  jest.resetModules();
  jest.clearAllMocks();

  if (fetchOverride) {
    (globalThis as { fetch?: typeof fetch }).fetch = fetchOverride;
  }

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

  jest.doMock("@naylence/runtime", () => ({
    getLogger: () => loggerMock,
  }));

  const module = await import("../trust-store/http-bundle-provider.js");
  return {
    HttpBundleProvider: module.HttpBundleProvider,
    fsMock,
    loggerMock,
  };
}

function createJsonBundle(version: number) {
  const payload = {
    version,
    roots: [
      {
        pem: SAMPLE_PEM,
        kid: "root",
        notBefore: "2024-01-01T00:00:00Z",
        notAfter: "2025-01-01T00:00:00Z",
      },
    ],
  } as const;
  const text = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(text);
  return { text, bytes };
}

const originalFetch = globalThis.fetch;
const originalWindow = globalThis.window;
const originalDocument = (globalThis as { document?: unknown }).document;

let consoleDebugSpy: ReturnType<typeof jest.spyOn>;
let consoleWarnSpy: ReturnType<typeof jest.spyOn>;

beforeEach(() => {
  if (originalFetch) {
    globalThis.fetch = originalFetch;
  } else {
    delete (globalThis as { fetch?: typeof fetch }).fetch;
  }

  if (originalWindow === undefined) {
    delete (globalThis as { window?: unknown }).window;
  } else {
    (globalThis as { window?: unknown }).window = originalWindow;
  }

  if (originalDocument === undefined) {
    delete (globalThis as { document?: unknown }).document;
  } else {
    (globalThis as { document?: unknown }).document = originalDocument;
  }

  consoleDebugSpy = jest.spyOn(console, "debug").mockImplementation(() => {});
  consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  if (originalFetch) {
    globalThis.fetch = originalFetch;
  } else {
    delete (globalThis as { fetch?: typeof fetch }).fetch;
  }

  if (originalWindow === undefined) {
    delete (globalThis as { window?: unknown }).window;
  } else {
    (globalThis as { window?: unknown }).window = originalWindow;
  }

  if (originalDocument === undefined) {
    delete (globalThis as { document?: unknown }).document;
  } else {
    (globalThis as { document?: unknown }).document = originalDocument;
  }

  consoleDebugSpy.mockRestore();
  consoleWarnSpy.mockRestore();
});

describe("HttpBundleProvider", () => {
  it("downloads and caches a JSON trust bundle", async () => {
    const originalProcess = globalThis.process;
    delete (globalThis as { process?: NodeJS.Process }).process;

    try {
    const { bytes } = createJsonBundle(1);
    const fetchResponse = new Response(bytes, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
    const fetchMock = jest.fn(async () => fetchResponse);
      const { HttpBundleProvider } = await setupModule(
      fetchMock as unknown as typeof fetch,
    );

    const provider = new HttpBundleProvider({
      url: "https://example.com/bundle.json",
      allowTofu: true,
      cacheKey: "test-cache-download",
    });

      const initializeSpy = jest.spyOn(
        provider as unknown as { initialize: () => Promise<void> },
        "initialize",
      );

      const first = await provider.getRoots();
      const second = await provider.getRoots();

      expect(initializeSpy).toHaveBeenCalled();
      expect(first).toHaveLength(1);
      expect(second).toBe(first);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      (globalThis as { process?: NodeJS.Process }).process = originalProcess;
    }
  });

  it("treats 304 responses as cache hits without rewriting the cache", async () => {
    const originalProcess = globalThis.process;
    delete (globalThis as { process?: NodeJS.Process }).process;

    try {
      const { bytes } = createJsonBundle(2);

      const freshResponse = new Response(bytes, {
        status: 200,
        headers: { ETag: '"etag-1"' },
      });
      const cachedResponse = new Response(null, {
        status: 304,
        headers: { ETag: '"etag-1"' },
      });
      const responses = [freshResponse, cachedResponse];

      const fetchMock = jest.fn(async () => {
        const next = responses.shift();
        if (!next) {
          throw new Error("unexpected fetch call");
        }
        return next;
      });
      const { HttpBundleProvider } = await setupModule(
        fetchMock as unknown as typeof fetch,
      );

      const provider = new HttpBundleProvider({
        url: "https://example.com/bundle.json",
        allowTofu: true,
        refreshIntervalMs: 60_000,
        cacheKey: "test-cache-304",
      });

      const first = await provider.getRoots();
      const baseNow = Date.now();
      const nowSpy = jest.spyOn(Date, "now").mockImplementation(() => baseNow + 120_000);
      const second = await provider.getRoots();
      nowSpy.mockRestore();

      expect(first).toHaveLength(1);
      expect(second).toEqual(first);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      (globalThis as { process?: NodeJS.Process }).process = originalProcess;
    }
  });

  it("rejects mismatched hash pins", async () => {
    const originalProcess = globalThis.process;
    delete (globalThis as { process?: NodeJS.Process }).process;

    try {
      const { bytes } = createJsonBundle(3);
      const fetchResponse = new Response(bytes, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
      const fetchMock = jest.fn(async () => fetchResponse);
      const { HttpBundleProvider } = await setupModule(
        fetchMock as unknown as typeof fetch,
      );

      const provider = new HttpBundleProvider({
        url: "https://example.com/bundle.json",
        hashPins: ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        cacheKey: "test-cache-hash-mismatch",
      });

      await expect(provider.getRoots()).rejects.toThrow("Trust bundle hash mismatch");
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      (globalThis as { process?: NodeJS.Process }).process = originalProcess;
    }
  });

  it("requires pins or TOFU in browser environments", async () => {
    const { HttpBundleProvider } = await setupModule();

    const fakeWindow = { document: {} };
    (globalThis as { window?: unknown }).window = fakeWindow;
    (globalThis as { document?: unknown }).document = fakeWindow.document;

    expect(() => new HttpBundleProvider({ url: "https://example.com" })).toThrow(
      "Browser environments require hash pin, SPKI allowlist, or TOFU",
    );
  });

  it("allows hash updates in TOFU mode after cache is established", async () => {
    const originalProcess = globalThis.process;
    delete (globalThis as { process?: NodeJS.Process }).process;

    try {
      const bundle1 = createJsonBundle(1);
      const bundle2 = createJsonBundle(2);

      let callCount = 0;
      const fetchMock = jest.fn(async () => {
        callCount += 1;
        const bundle = callCount === 1 ? bundle1 : bundle2;
        return new Response(bundle.bytes, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      });

      const { HttpBundleProvider, fsMock } = await setupModule(
        fetchMock as unknown as typeof fetch,
      );

      // Simulate cache with old hash
      const cachedHash = "OLD_HASH_VALUE";
      fsMock.readFile.mockResolvedValueOnce(
        JSON.stringify({
          anchors: [{ pem: SAMPLE_PEM, kid: "root" }],
          etag: null,
          fetchedAt: Date.now() - 86_400_000 - 1000, // 24+ hours ago
          hash: cachedHash,
          version: 1,
        }),
      );

      const provider = new HttpBundleProvider({
        url: "https://example.com/bundle.json",
        allowTofu: true,
        cacheKey: "test-tofu-hash-update",
      });

      // This should succeed even though hash changed, because TOFU allows updates
      const roots = await provider.getRoots();

      expect(roots).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      (globalThis as { process?: NodeJS.Process }).process = originalProcess;
    }
  });

  it("accepts hash rotation without version upgrade in relaxed dev mode", async () => {
    const originalProcess = globalThis.process;
    delete (globalThis as { process?: NodeJS.Process }).process;

    try {
      const bundle = createJsonBundle(1);
      const fetchMock = jest.fn(async () =>
        new Response(bundle.bytes, {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

      const { HttpBundleProvider, fsMock } = await setupModule(
        fetchMock as unknown as typeof fetch,
      );

      fsMock.readFile.mockResolvedValueOnce(
        JSON.stringify({
          anchors: [{ pem: SAMPLE_PEM, kid: "root" }],
          etag: null,
          fetchedAt: Date.now(),
          hash: "OLD_HASH",
          version: 1,
        }),
      );

      const provider = new HttpBundleProvider({
        url: "http://127.0.0.1:3000/.well-known/naylence/trust-bundle.json",
        allowInsecureHttp: true,
        cacheKey: "dev-hash-rotation",
      });

      const roots = await provider.getRoots();

      expect(roots).toHaveLength(1);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      (globalThis as { process?: NodeJS.Process }).process = originalProcess;
    }
  });

  it("forces a refresh for loopback dev bundles even when cache looks fresh", async () => {
    const fetchResponse = new Response(createJsonBundle(5).bytes, {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
    const fetchMock = jest.fn(async () => fetchResponse);
    const { HttpBundleProvider, fsMock } = await setupModule(
      fetchMock as unknown as typeof fetch,
    );

    fsMock.readFile.mockResolvedValueOnce(
      JSON.stringify({
        anchors: [{ pem: SAMPLE_PEM, kid: "root" }],
        etag: "\"cached\"",
        fetchedAt: Date.now() - 5_000,
        hash: "dev_hash",
        version: 1,
      }),
    );

    const provider = new HttpBundleProvider({
      url: "http://localhost:3000/.well-known/naylence/trust-bundle.json",
      allowInsecureHttp: true,
      allowTofu: true,
      cacheKey: "dev-force-refresh",
    });

    const roots = await provider.getRoots();

    expect(roots).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
