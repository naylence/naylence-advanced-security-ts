import { DeliveryOriginType } from "naylence-core";

import { X5CKeyManager } from "../x5c-key-manager.js";
const expirationQueue: Date[] = [];

type KeyRecordLike = Record<string, unknown> & { kid: string };

interface KeyStoreLike {
  addKeys(keys: Array<Record<string, unknown>>, physicalPath: string): Promise<void>;
  addKey(kid: string, jwk: KeyRecordLike): Promise<void>;
  getKey(kid: string): Promise<KeyRecordLike>;
  hasKey(kid: string): Promise<boolean>;
  getKeys(): Promise<Iterable<KeyRecordLike>>;
  getKeysForPath(physicalPath: string): Promise<Iterable<KeyRecordLike>>;
  getKeysGroupedByPath(): Promise<Record<string, KeyRecordLike[]>>;
  removeKeysForPath(physicalPath: string): Promise<number>;
  removeKey(kid: string): Promise<boolean>;
}

jest.mock("../../cert/util.js", () => {
  return {
    validateJwkX5cCertificate: jest.fn(() => ({ isValid: true })),
  };
});

jest.mock("@peculiar/x509", () => {
  class MockX509Certificate {
    public readonly notAfter: Date;

    constructor(_raw: Uint8Array) {
      this.notAfter = expirationQueue.shift() ?? new Date(Date.now() + 60_000);
    }
  }

  return {
    X509Certificate: MockX509Certificate,
  };
});

function createValidJwk(kid: string): Record<string, unknown> {
  return {
    kid,
    kty: "OKP",
    crv: "Ed25519",
    use: "sig",
    x: "abc",
    x5c: ["AAAA"],
  };
}

function createMockKeyStore() {
  const mocks = {
    addKeys: jest.fn(async (_keys: Array<Record<string, unknown>>, _physicalPath: string) => {}),
    addKey: jest.fn(async (_kid: string, _jwk: KeyRecordLike) => {}),
    getKey: jest.fn(async (_kid: string) => ({}) as KeyRecordLike),
    hasKey: jest.fn(async (_kid: string) => false),
    getKeys: jest.fn(async () => [] as KeyRecordLike[]),
    getKeysForPath: jest.fn(async (_physicalPath: string) => [] as KeyRecordLike[]),
    getKeysGroupedByPath: jest.fn(async () => ({}) as Record<string, KeyRecordLike[]>),
    removeKeysForPath: jest.fn(async (_physicalPath: string) => 0),
    removeKey: jest.fn(async (_kid: string) => false),
  };

  return { store: mocks as unknown as KeyStoreLike, mocks };
}

function setTrustStore(path: string | null): void {
  if (typeof process === "undefined" || !process.env) {
    return;
  }

  if (path === null) {
    delete process.env.FAME_TRUST_STORE_PATH;
    delete process.env.FAME_CA_CERT_FILE;
    return;
  }

  process.env.FAME_TRUST_STORE_PATH = path;
}

async function attachNode(
  manager: X5CKeyManager,
  options: { physicalPath?: string; hasParent?: boolean } = {}
): Promise<any> {
  const node = {
    physicalPath: options.physicalPath ?? "/parent/node",
    hasParent: options.hasParent ?? false,
  } as any;

  await manager.onNodeStarted(node);
  return node;
}

describe("X5CKeyManager", () => {
  const validateSpy = jest.requireMock("../../cert/util.js")
    .validateJwkX5cCertificate as jest.Mock<{ isValid: boolean; error?: string }>;

  beforeEach(() => {
    jest.clearAllMocks();
    setTrustStore(null);
    expirationQueue.length = 0;
  });

  it("validates x5c keys when trust store configured", async () => {
    const { store, mocks } = createMockKeyStore();
    const manager = new X5CKeyManager({ keyStore: store });
    setTrustStore("/etc/trust.pem");
    const node = await attachNode(manager);

    const key = createValidJwk("kid-1");
    await manager.addKeys({
      keys: [key],
      physicalPath: "/parent/node/child",
      systemId: "child",
      origin: DeliveryOriginType.DOWNSTREAM,
    });

    expect(validateSpy).toHaveBeenCalledTimes(1);
    expect(validateSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        jwk: expect.objectContaining({ kid: "kid-1" }),
        trustStorePem: "/etc/trust.pem",
        enforceNameConstraints: true,
      })
    );
    expect(mocks.addKeys).toHaveBeenCalledTimes(1);

    await manager.onNodeStopped(node);
  });

  it("rejects invalid downstream certificates", async () => {
    validateSpy.mockReturnValueOnce({ isValid: false, error: "bad" });
    const { store, mocks } = createMockKeyStore();
    const manager = new X5CKeyManager({ keyStore: store });
    setTrustStore("/etc/trust.pem");
    const node = await attachNode(manager);

    const key = createValidJwk("kid-2");
    await manager.addKeys({
      keys: [key],
      physicalPath: "/parent/node/child",
      systemId: "child",
      origin: DeliveryOriginType.DOWNSTREAM,
    });

    expect(validateSpy).toHaveBeenCalled();
    expect(mocks.addKeys).not.toHaveBeenCalled();

    await manager.onNodeStopped(node);
  });

  it("accepts invalid peer certificates with warning", async () => {
    validateSpy.mockReturnValueOnce({ isValid: false, error: "bad" });
    const { store, mocks } = createMockKeyStore();
    const manager = new X5CKeyManager({ keyStore: store });
    setTrustStore("/etc/trust.pem");
    const node = await attachNode(manager);

    const key = createValidJwk("kid-3");
    await manager.addKeys({
      keys: [key],
      physicalPath: "/peer",
      systemId: "peer",
      origin: DeliveryOriginType.PEER,
    });

    expect(mocks.addKeys).toHaveBeenCalledTimes(1);
  const addCall = mocks.addKeys.mock.calls[0] as unknown[];
  const storedKeys = addCall[0] as Array<Record<string, unknown>>;
    expect(storedKeys).toHaveLength(1);
    expect(storedKeys[0].kid).toBe("kid-3");

    await manager.onNodeStopped(node);
  });

  it("purges expired certificates using x509 module", async () => {
    const { store, mocks } = createMockKeyStore();
    const manager = new X5CKeyManager({ keyStore: store });

    const expiredKey = {
      kid: "expired",
      x5c: ["AAAA"],
      physical_path: "/path/expired",
    } as unknown as KeyRecordLike;

    const validKey = {
      kid: "valid",
      x5c: ["AAAA"],
      physical_path: "/path/valid",
    } as unknown as KeyRecordLike;

    mocks.getKeysGroupedByPath.mockResolvedValueOnce({
      "/path": [expiredKey, validKey],
    });

  mocks.removeKey.mockImplementation(async (kid: string) => kid === "expired");

    expirationQueue.push(new Date(Date.now() - 1_000));
    expirationQueue.push(new Date(Date.now() + 60_000));

    const purged = await manager.purgeExpiredCertificates();

    expect(purged).toBe(1);
    expect(mocks.removeKey).toHaveBeenCalledTimes(1);
    expect(mocks.removeKey).toHaveBeenCalledWith("expired");
  });
});
