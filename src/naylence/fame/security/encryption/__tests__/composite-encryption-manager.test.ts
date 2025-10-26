import type { FameEnvelope } from "@naylence/core";
import {
  CompositeEncryptionManager,
  type CompositeEncryptionManagerDependencies,
} from "../composite-encryption-manager.js";
import { CompositeEncryptionManagerFactory } from "../composite-encryption-manager-factory.js";
import {
  EncryptionManagerFactory,
  type EncryptionManagerConfig,
  type EncryptionFactoryDependencies,
  EncryptionManager,
  EncryptionOptions,
  EncryptionResult,
  SecureChannelManager,
  CryptoProvider,
  KeyProvider,
  NodeLike,
  AttachInfo,
} from "@naylence/runtime";

class RecordingSealedEncryptionManager implements EncryptionManager {
  public readonly priority = 500;
  public readonly encryptCalls: Array<{
    envelope: FameEnvelope;
    opts?: EncryptionOptions;
  }>;
  public readonly decryptCalls: Array<{
    envelope: FameEnvelope;
    opts?: EncryptionOptions;
  }>;
  public readonly keyNotifications: string[];
  public readonly nodeStarted: NodeLike[];
  public readonly nodeStopped: NodeLike[];
  public readonly upstreamAttached: Array<{ node: NodeLike; info: AttachInfo }>;

  constructor(public readonly label: string) {
    this.encryptCalls = [];
    this.decryptCalls = [];
    this.keyNotifications = [];
    this.nodeStarted = [];
    this.nodeStopped = [];
    this.upstreamAttached = [];
  }

  async encryptEnvelope(envelope: FameEnvelope, opts?: EncryptionOptions) {
    this.encryptCalls.push(opts ? { envelope, opts } : { envelope });
    return EncryptionResult.ok(envelope);
  }

  async decryptEnvelope(envelope: FameEnvelope, opts?: EncryptionOptions) {
    this.decryptCalls.push(opts ? { envelope, opts } : { envelope });
    return envelope;
  }

  async notifyKeyAvailable?(keyId: string) {
    this.keyNotifications.push(keyId);
  }

  async onNodeStarted?(node: NodeLike) {
    this.nodeStarted.push(node);
  }

  async onNodeAttachToUpstream?(node: NodeLike, info: AttachInfo) {
    this.upstreamAttached.push({ node, info });
  }

  async onNodeStopped?(node: NodeLike) {
    this.nodeStopped.push(node);
  }
}

class RecordingChannelEncryptionManager extends RecordingSealedEncryptionManager {
  public readonly channelEstablished: string[] = [];
  public readonly channelFailed: Array<{ channelId: string; reason?: string }> =
    [];

  constructor() {
    super("channel");
  }

  async notifyChannelEstablished?(channelId: string) {
    this.channelEstablished.push(channelId);
  }

  async notifyChannelFailed?(channelId: string, reason?: string) {
    this.channelFailed.push(
      reason === undefined ? { channelId } : { channelId, reason },
    );
  }
}

abstract class BaseTestFactory extends EncryptionManagerFactory<EncryptionManagerConfig> {
  public creationCount = 0;
  public readonly createdManagers: RecordingSealedEncryptionManager[] = [];
  public lastDependencies: EncryptionFactoryDependencies | undefined;

  constructor(
    public readonly type: string,
    public readonly priority = 100,
  ) {
    super();
  }

  public abstract create(
    config?: EncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager>;

  public getSupportedAlgorithms(): readonly string[] {
    return [];
  }

  public getEncryptionType(): string {
    return "sealed";
  }

  public supportsOptions(_opts?: EncryptionOptions | null): boolean {
    return false;
  }

  protected recordCreate(dependencies?: EncryptionFactoryDependencies) {
    this.creationCount += 1;
    this.lastDependencies = dependencies;
  }
}

class TestSealedFactory extends BaseTestFactory {
  constructor(private readonly algorithm: string = "X25519") {
    super("TestSealedFactory", 1000);
  }

  public override getSupportedAlgorithms(): readonly string[] {
    return [this.algorithm];
  }

  public override getEncryptionType(): string {
    return "sealed";
  }

  public override supportsOptions(opts?: EncryptionOptions | null): boolean {
    const candidate = opts as EncryptionOptions & { encryption_type?: string };
    return (
      candidate?.encryptionType === "sealed" ||
      candidate?.encryption_type === "sealed"
    );
  }

  public override async create(
    _config?: EncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [
      EncryptionFactoryDependencies | undefined,
    ];
    this.recordCreate(dependencies);
    const manager = new RecordingSealedEncryptionManager("sealed");
    this.createdManagers.push(manager);
    return manager;
  }
}

class TestChannelFactory extends BaseTestFactory {
  constructor() {
    super("TestChannelFactory", 1000);
  }

  public override getSupportedAlgorithms(): readonly string[] {
    return ["chacha20-poly1305-channel"];
  }

  public override getEncryptionType(): string {
    return "channel";
  }

  public override supportsOptions(opts?: EncryptionOptions | null): boolean {
    const candidate = opts as EncryptionOptions & { encryption_type?: string };
    return (
      candidate?.encryptionType === "channel" ||
      candidate?.encryption_type === "channel"
    );
  }

  public override async create(
    _config?: EncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [
      EncryptionFactoryDependencies | undefined,
    ];
    this.recordCreate(dependencies);
    const manager = new RecordingChannelEncryptionManager();
    this.createdManagers.push(manager);
    return manager;
  }
}

class TestAltSealedFactory extends BaseTestFactory {
  constructor() {
    super("TestAltSealedFactory", 950);
  }

  public override getSupportedAlgorithms(): readonly string[] {
    return ["ECDH-ES+A256GCM"];
  }

  public override getEncryptionType(): string {
    return "sealed";
  }

  public override supportsOptions(opts?: EncryptionOptions | null): boolean {
    const candidate = opts as EncryptionOptions & { encryption_type?: string };
    return (
      candidate?.encryptionType === "sealed-alt" ||
      candidate?.encryption_type === "sealed-alt"
    );
  }

  public override async create(
    _config?: EncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [
      EncryptionFactoryDependencies | undefined,
    ];
    this.recordCreate(dependencies);
    const manager = new RecordingSealedEncryptionManager("sealed-alt");
    this.createdManagers.push(manager);
    return manager;
  }
}

class FakeRegistry {
  private readonly factories: EncryptionManagerFactory[] = [];
  private readonly algorithmMap = new Map<string, EncryptionManagerFactory>();
  private readonly typeMap = new Map<string, EncryptionManagerFactory[]>();

  constructor(initialFactories: EncryptionManagerFactory[] = []) {
    for (const factory of initialFactories) {
      this.register(factory);
    }
  }

  public register(factory: EncryptionManagerFactory): void {
    if (this.factories.includes(factory)) {
      return;
    }

    this.factories.push(factory);

    for (const algorithm of factory.getSupportedAlgorithms()) {
      const existing = this.algorithmMap.get(algorithm);
      if (!existing || factory.getPriority() > existing.getPriority()) {
        this.algorithmMap.set(algorithm, factory);
      }
    }

    const type = factory.getEncryptionType();
    const list = this.typeMap.get(type) ?? [];
    list.push(factory);
    list.sort((a, b) => b.getPriority() - a.getPriority());
    this.typeMap.set(type, list);
  }

  public getFactoryForOptions(
    opts?: EncryptionOptions | null,
  ): EncryptionManagerFactory | undefined {
    for (const factory of this.factories) {
      if (factory.supportsOptions(opts ?? undefined)) {
        return factory;
      }
    }
    return undefined;
  }

  public getFactoryForAlgorithm(
    algorithm: string,
  ): EncryptionManagerFactory | undefined {
    return this.algorithmMap.get(algorithm);
  }

  public getFactoriesByType(type: string): readonly EncryptionManagerFactory[] {
    return this.typeMap.get(type) ?? [];
  }
}

class TestCompositeEncryptionManager extends CompositeEncryptionManager {
  constructor(
    deps: CompositeEncryptionManagerDependencies,
    registry: FakeRegistry,
  ) {
    super(deps);
    (this as any).factoryRegistry = registry;
  }
}

function createSecureChannelManager(): SecureChannelManager {
  return {
    channels: {},
    generateOpenFrame: jest.fn(),
    handleOpenFrame: jest.fn(),
    handleAcceptFrame: jest.fn(),
    handleCloseFrame: jest.fn(),
    isChannelEncrypted: jest.fn().mockReturnValue(false),
    hasChannel: jest.fn().mockReturnValue(false),
    getChannelInfo: jest.fn().mockReturnValue(null),
    closeChannel: jest.fn(),
    cleanupExpiredChannels: jest.fn().mockReturnValue(0),
    addChannel: jest.fn(),
    removeChannel: jest.fn().mockReturnValue(false),
  };
}

function createKeyProvider(): KeyProvider {
  return {
    getKey: jest.fn(async () => ({}) as any),
    getKeysForPath: jest.fn(async () => []),
  };
}

function createCryptoProvider(): CryptoProvider {
  return {};
}

function createNodeLike(): NodeLike {
  const noopAsync = jest.fn(async () => undefined);
  const noopPromise = jest.fn(async () => ({}) as any);
  return {
    id: "node-1",
    sid: null,
    physicalPath: "/root",
    acceptedLogicals: new Set<string>(),
    envelopeFactory: {} as any,
    deliveryPolicy: null,
    defaultBindingPath: "/",
    hasParent: false,
    securityManager: null,
    admissionClient: null,
    eventListeners: [],
    upstreamConnector: null,
    publicUrl: null,
    storageProvider: {} as any,
    cryptoProvider: createCryptoProvider() as any,
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    start: noopAsync,
    stop: noopAsync,
    bind: noopPromise,
    unbind: noopAsync,
    send: noopPromise,
    listen: noopPromise,
    listenRpc: noopPromise,
    invoke: noopPromise,
    invokeByCapability: noopPromise,
    invokeStream: async function* () {
      return undefined;
    },
    invokeByCapabilityStream: async function* () {
      return undefined;
    },
    deliver: noopAsync,
    deliverLocal: noopAsync,
    forwardUpstream: noopAsync,
    hasLocal: jest.fn().mockReturnValue(false),
    gatherSupportedCallbackGrants: jest.fn().mockReturnValue([]),
    dispatchEvent: noopAsync,
    dispatchEnvelopeEvent: jest.fn(async () => null),
  } as unknown as NodeLike;
}

function createEnvelope(): FameEnvelope {
  return {
    id: "env-1",
    sec: {
      enc: {
        alg: "X25519",
      },
    },
  } as FameEnvelope;
}

function createDependencies(
  overrides: Partial<CompositeEncryptionManagerDependencies> = {},
): CompositeEncryptionManagerDependencies {
  return {
    secureChannelManager: createSecureChannelManager(),
    keyProvider: createKeyProvider(),
    cryptoProvider: null,
    nodeLike: null,
    ...overrides,
  };
}

describe("CompositeEncryptionManagerFactory", () => {
  it("throws when secureChannelManager dependency is missing", async () => {
    const factory = new CompositeEncryptionManagerFactory();
    await expect(
      factory.create(null, {
        keyProvider: createKeyProvider(),
      }),
    ).rejects.toThrow("secureChannelManager");
  });

  it("throws when keyProvider dependency is missing", async () => {
    const factory = new CompositeEncryptionManagerFactory();
    await expect(
      factory.create(null, {
        secureChannelManager: createSecureChannelManager(),
      }),
    ).rejects.toThrow("keyProvider");
  });

  it("creates a composite manager when dependencies provided", async () => {
    const factory = new CompositeEncryptionManagerFactory();
    const manager = await factory.create(null, {
      secureChannelManager: createSecureChannelManager(),
      keyProvider: createKeyProvider(),
    });

    expect(manager).toBeInstanceOf(CompositeEncryptionManager);
  });
});

describe("CompositeEncryptionManager behavior", () => {
  let sealedFactory: TestSealedFactory;
  let channelFactory: TestChannelFactory;
  let registryStub: FakeRegistry;
  let composite: TestCompositeEncryptionManager;

  beforeEach(() => {
    sealedFactory = new TestSealedFactory();
    channelFactory = new TestChannelFactory();
    registryStub = new FakeRegistry([sealedFactory, channelFactory]);
    composite = new TestCompositeEncryptionManager(
      createDependencies(),
      registryStub,
    );
  });

  it("skips encryption when no matching manager exists", async () => {
    const envelope = createEnvelope();
    const result = await composite.encryptEnvelope(envelope, {
      encryptionType: "unknown",
    });

    expect(result.status).toBe("SKIPPED");
    expect(sealedFactory.creationCount).toBe(0);
    expect(channelFactory.creationCount).toBe(0);
  });

  it("delegates encryption to matching manager based on options", async () => {
    const envelope = createEnvelope();
    const result = await composite.encryptEnvelope(envelope, {
      encryptionType: "sealed",
    });

    expect(result.status).toBe("OK");
    expect(sealedFactory.creationCount).toBe(1);
    expect(sealedFactory.createdManagers[0].encryptCalls).toHaveLength(1);
  });

  it("delegates decryption based on envelope algorithm", async () => {
    const envelope = createEnvelope();
    await composite.encryptEnvelope(envelope, { encryptionType: "sealed" });
    sealedFactory.createdManagers[0].decryptCalls.length = 0;

    await composite.decryptEnvelope(envelope);
    expect(sealedFactory.createdManagers[0].decryptCalls).toHaveLength(1);
  });

  it("does not instantiate channel manager when notifying without prior creation", async () => {
    await composite.notifyChannelEstablished("channel-1");

    expect(channelFactory.creationCount).toBe(0);
  });

  it("forwards channel notifications to existing manager", async () => {
    await composite.encryptEnvelope(createEnvelope(), {
      encryptionType: "channel",
    });
    const channelManager = channelFactory
      .createdManagers[0] as RecordingChannelEncryptionManager;

    await composite.notifyChannelEstablished("channel-42");
    await composite.notifyChannelFailed("channel-42", "timeout");

    expect(channelManager.channelEstablished).toEqual(["channel-42"]);
    expect(channelManager.channelFailed).toEqual([
      { channelId: "channel-42", reason: "timeout" },
    ]);
  });

  it("forwards key availability notifications to sealed manager", async () => {
    await composite.encryptEnvelope(createEnvelope(), {
      encryptionType: "sealed",
    });
    const sealedManager = sealedFactory.createdManagers[0];

    await composite.notifyKeyAvailable("kid-1");
    expect(sealedManager.keyNotifications).toEqual(["kid-1"]);
  });

  it("initializes default managers and propagates node events", async () => {
    const node = createNodeLike();
    const attachInfo: AttachInfo = {
      systemId: "sys-1",
      targetSystemId: "parent",
      targetPhysicalPath: "/root",
      assignedPath: "/child",
    };

    await composite.onNodeStarted(node);
    await composite.onNodeAttachToUpstream(node, attachInfo);
    await composite.onNodeStopped(node);

    expect(sealedFactory.creationCount).toBeGreaterThanOrEqual(1);
    expect(channelFactory.creationCount).toBeGreaterThanOrEqual(1);

    const sealedManager = sealedFactory.createdManagers[0];
    expect(sealedManager.nodeStarted).toEqual([node]);
    expect(sealedManager.upstreamAttached).toEqual([
      { node, info: attachInfo },
    ]);
    expect(sealedManager.nodeStopped).toEqual([node]);
  });

  it("applies node context to managers created after node start", async () => {
    const node = createNodeLike();
    const attachInfo: AttachInfo = {
      systemId: "sys-2",
      targetSystemId: "parent",
      targetPhysicalPath: "/root",
      assignedPath: "/child",
    };

    await composite.onNodeStarted(node);
    await composite.onNodeAttachToUpstream(node, attachInfo);

    const altFactory = new TestAltSealedFactory();
    registryStub.register(altFactory);

    await composite.encryptEnvelope(createEnvelope(), {
      encryptionType: "sealed-alt",
    });

    expect(altFactory.creationCount).toBe(1);
    const altManager = altFactory.createdManagers[0];
    expect(altManager.nodeStarted).toEqual([node]);
    expect(altManager.upstreamAttached).toEqual([{ node, info: attachInfo }]);
  });
});
