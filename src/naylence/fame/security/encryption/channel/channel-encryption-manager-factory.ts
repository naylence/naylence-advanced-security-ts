import {
  ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  EncryptionManagerFactory,
  type EncryptionManagerConfig,
  type EncryptionFactoryDependencies,
} from "naylence-runtime";
import {
  type EncryptionManager,
  type EncryptionOptions,
} from "naylence-runtime";
import type { SecureChannelManager } from "naylence-runtime";
import type { NodeLike } from "naylence-runtime";
import { getLogger } from "naylence-runtime";
import { ChannelEncryptionManager, type ChannelEncryptionManagerDependencies } from "./channel-encryption-manager.js";

const logger = getLogger("naylence.advanced.encryption.channel.factory");

export interface ChannelEncryptionManagerConfig extends EncryptionManagerConfig {
  readonly type: "ChannelEncryptionManager";
  readonly priority: number;
  readonly supportedAlgorithms: readonly string[];
  readonly encryptionType: string;
}

const DEFAULT_SUPPORTED_ALGORITHMS = ["chacha20-poly1305-channel"] as const;

export const FACTORY_META = {
  base: ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  key: "ChannelEncryptionManager",
} as const;

export class ChannelEncryptionManagerFactory extends EncryptionManagerFactory<ChannelEncryptionManagerConfig> {
  public readonly type = FACTORY_META.key;
  public readonly priority: number;

  private readonly supportedAlgorithms: readonly string[];
  private readonly encryptionType: string;

  constructor(config?: Partial<ChannelEncryptionManagerConfig> | null) {
    super();
    this.supportedAlgorithms = config?.supportedAlgorithms ?? DEFAULT_SUPPORTED_ALGORITHMS;
    this.encryptionType = config?.encryptionType ?? "channel";
    this.priority = config?.priority ?? 90;
  }

  public getSupportedAlgorithms(): readonly string[] {
    return this.supportedAlgorithms;
  }

  public getEncryptionType(): string {
    return this.encryptionType;
  }

  public supportsOptions(opts?: EncryptionOptions | null): boolean {
    if (!opts) {
      return false;
    }

    const candidate = (opts as Record<string, unknown>).encryption_type;
    const normalized = typeof candidate === "string" ? candidate : opts.encryptionType;
    return normalized === "channel";
  }

  public async create(
    _config?: ChannelEncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [EncryptionFactoryDependencies | undefined];
    const resolvedDependencies = this.resolveDependencies(dependencies);

    logger.debug("creating_channel_encryption_manager", {
      has_secure_channel_manager: Boolean(resolvedDependencies.secureChannelManager),
      has_node_like: Boolean(resolvedDependencies.nodeLike),
      has_task_spawner: Boolean(resolvedDependencies.taskSpawner),
    });

    return new ChannelEncryptionManager(resolvedDependencies);
  }

  private resolveDependencies(
    dependencies?: EncryptionFactoryDependencies
  ): ChannelEncryptionManagerDependencies {
    if (!dependencies) {
      return {};
    }

    const secureChannelManager = this.resolveSecureChannelManager(dependencies);
    const nodeLike = this.resolveNodeLike(dependencies);
    const taskSpawner = this.resolveTaskSpawner(dependencies, nodeLike);

    return {
      secureChannelManager,
      nodeLike,
      taskSpawner: taskSpawner ?? null,
    };
  }

  private resolveSecureChannelManager(
    dependencies: EncryptionFactoryDependencies
  ): SecureChannelManager | null {
    const direct = dependencies.secureChannelManager as SecureChannelManager | undefined;
    const snake = dependencies["secure_channel_manager"] as SecureChannelManager | undefined;
    return direct ?? snake ?? null;
  }

  private resolveNodeLike(dependencies: EncryptionFactoryDependencies): NodeLike | null {
    const direct = dependencies.nodeLike as NodeLike | undefined;
    const camel = dependencies["node_like"] as NodeLike | undefined;
    return direct ?? camel ?? null;
  }

  private resolveTaskSpawner(
    dependencies: EncryptionFactoryDependencies,
    nodeLike: NodeLike | null
  ): ChannelEncryptionManagerDependencies["taskSpawner"] {
    const direct = dependencies.taskSpawner as ChannelEncryptionManagerDependencies["taskSpawner"];
    if (direct && typeof direct.spawn === "function") {
      return direct;
    }

    const snake = dependencies["task_spawner"] as ChannelEncryptionManagerDependencies["taskSpawner"];
    if (snake && typeof snake.spawn === "function") {
      return snake;
    }

    if (nodeLike) {
      const candidate = nodeLike as unknown as { spawn?: unknown };
      if (typeof candidate.spawn === "function") {
        return candidate as ChannelEncryptionManagerDependencies["taskSpawner"];
      }
    }

    return null;
  }
}

export default ChannelEncryptionManagerFactory;
