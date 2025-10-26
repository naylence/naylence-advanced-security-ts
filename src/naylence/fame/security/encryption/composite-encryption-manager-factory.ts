import {
  ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  EncryptionManagerFactory,
  type EncryptionManagerConfig,
  type EncryptionFactoryDependencies,
  type EncryptionManager,
  type EncryptionOptions,
} from "@naylence/runtime";
import type {
  SecureChannelManager,
  CryptoProvider,
  KeyProvider,
  NodeLike,
} from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";

import { CompositeEncryptionManager } from "./composite-encryption-manager.js";

const logger = getLogger(
  "naylence.fame.security.encryption.composite_encryption_manager_factory",
);

const DEFAULT_PRIORITY = 1000;
const DEFAULT_ENCRYPTION_TYPE = "composite" as const;

export const FACTORY_META = {
  base: ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  key: "CompositeEncryptionManager",
} as const;

export interface CompositeEncryptionManagerConfig
  extends EncryptionManagerConfig {
  readonly type: "CompositeEncryptionManager";
  readonly defaultAlgo?: string | null;
  readonly supportedSealedAlgorithms?: readonly string[] | null;
  readonly supportedChannelAlgorithms?: readonly string[] | null;
}

interface ResolvedDependencies {
  readonly secureChannelManager: SecureChannelManager;
  readonly keyProvider: KeyProvider;
  readonly cryptoProvider: CryptoProvider | null;
  readonly nodeLike: NodeLike | null;
}

export class CompositeEncryptionManagerFactory extends EncryptionManagerFactory<CompositeEncryptionManagerConfig> {
  public readonly type = FACTORY_META.key;
  public readonly isDefault = true;
  public readonly priority: number;

  private readonly supportedAlgorithms: readonly string[];
  private readonly encryptionType: string;
  private readonly supportedSealedAlgorithms?: readonly string[] | null;
  private readonly supportedChannelAlgorithms?: readonly string[] | null;

  constructor(config?: Partial<CompositeEncryptionManagerConfig> | null) {
    super();

    this.priority = config?.priority ?? DEFAULT_PRIORITY;
    this.supportedAlgorithms = config?.supportedAlgorithms ?? [];
    this.encryptionType = config?.encryptionType ?? DEFAULT_ENCRYPTION_TYPE;
    this.supportedSealedAlgorithms = config?.supportedSealedAlgorithms ?? null;
    this.supportedChannelAlgorithms =
      config?.supportedChannelAlgorithms ?? null;
  }

  public getSupportedAlgorithms(): readonly string[] {
    return this.supportedAlgorithms;
  }

  public getEncryptionType(): string {
    return this.encryptionType;
  }

  public supportsOptions(_opts?: EncryptionOptions | null): boolean {
    return true;
  }

  public async create(
    config?: CompositeEncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [
      EncryptionFactoryDependencies | undefined,
    ];
    const resolved = this.resolveDependencies(dependencies);

    const runtimeConfig =
      (config as Partial<CompositeEncryptionManagerConfig> | null) ?? null;
    const supportedSealedAlgorithms =
      runtimeConfig?.supportedSealedAlgorithms ??
      this.supportedSealedAlgorithms ??
      undefined;
    const supportedChannelAlgorithms =
      runtimeConfig?.supportedChannelAlgorithms ??
      this.supportedChannelAlgorithms ??
      undefined;

    logger.debug("creating_composite_encryption_manager", {
      has_secure_channel_manager: Boolean(resolved.secureChannelManager),
      has_key_provider: Boolean(resolved.keyProvider),
      has_crypto_provider: Boolean(resolved.cryptoProvider),
      has_node_like: Boolean(resolved.nodeLike),
      supported_sealed_algorithms: supportedSealedAlgorithms,
      supported_channel_algorithms: supportedChannelAlgorithms,
    });

    return new CompositeEncryptionManager({
      secureChannelManager: resolved.secureChannelManager,
      keyProvider: resolved.keyProvider,
      cryptoProvider: resolved.cryptoProvider,
      nodeLike: resolved.nodeLike,
      ...(supportedSealedAlgorithms !== undefined
        ? { supportedSealedAlgorithms }
        : {}),
      ...(supportedChannelAlgorithms !== undefined
        ? { supportedChannelAlgorithms }
        : {}),
    });
  }

  private resolveDependencies(
    dependencies?: EncryptionFactoryDependencies,
  ): ResolvedDependencies {
    const secureChannelManager = this.resolveSecureChannelManager(dependencies);
    if (!secureChannelManager) {
      throw new Error(
        "CompositeEncryptionManager requires secureChannelManager dependency. Provide a SecureChannelManager instance.",
      );
    }

    const keyProvider = this.resolveKeyProvider(dependencies);
    if (!keyProvider) {
      throw new Error(
        "CompositeEncryptionManager requires keyProvider dependency. Provide a KeyProvider instance.",
      );
    }

    return {
      secureChannelManager,
      keyProvider,
      cryptoProvider: this.resolveCryptoProvider(dependencies),
      nodeLike: this.resolveNodeLike(dependencies),
    };
  }

  private resolveSecureChannelManager(
    dependencies?: EncryptionFactoryDependencies,
  ): SecureChannelManager | null {
    if (!dependencies) {
      return null;
    }

    const direct = dependencies.secureChannelManager as
      | SecureChannelManager
      | undefined;
    const snake = dependencies["secure_channel_manager"] as
      | SecureChannelManager
      | undefined;
    return direct ?? snake ?? null;
  }

  private resolveKeyProvider(
    dependencies?: EncryptionFactoryDependencies,
  ): KeyProvider | null {
    if (!dependencies) {
      return null;
    }

    const direct = dependencies.keyProvider as KeyProvider | undefined;
    const snake = dependencies["key_provider"] as KeyProvider | undefined;
    return direct ?? snake ?? null;
  }

  private resolveCryptoProvider(
    dependencies?: EncryptionFactoryDependencies,
  ): CryptoProvider | null {
    if (!dependencies) {
      return null;
    }

    const direct = dependencies.cryptoProvider as CryptoProvider | undefined;
    const snake = dependencies["crypto_provider"] as CryptoProvider | undefined;
    return direct ?? snake ?? null;
  }

  private resolveNodeLike(
    dependencies?: EncryptionFactoryDependencies,
  ): NodeLike | null {
    if (!dependencies) {
      return null;
    }

    const direct = dependencies.nodeLike as NodeLike | undefined;
    const camel = dependencies["node_like"] as NodeLike | undefined;
    return direct ?? camel ?? null;
  }
}

export default CompositeEncryptionManagerFactory;
