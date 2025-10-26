import type { FameEnvelope } from "@naylence/core";
import type {
  EncryptionFactoryDependencies,
  EncryptionManagerFactory,
  SecureChannelManager,
  CryptoProvider,
  KeyProvider,
  NodeEventListener,
  NodeLike,
  AttachInfo,
} from "@naylence/runtime";
import {
  EncryptionResult,
  type EncryptionManager,
  type EncryptionOptions,
  getLogger,
} from "@naylence/runtime";

import { getEncryptionManagerFactoryRegistry } from "./encryption-manager-registry.js";

const logger = getLogger(
  "naylence.fame.security.encryption.composite_encryption_manager",
);

const DEFAULT_SEALED_ALGORITHMS = [
  "X25519",
  "ECDH-ES+A256GCM",
  "chacha20-poly1305",
  "aes-256-gcm",
] as const;
const DEFAULT_CHANNEL_ALGORITHMS = ["chacha20-poly1305-channel"] as const;

export interface CompositeEncryptionManagerDependencies {
  readonly secureChannelManager?: SecureChannelManager | null;
  readonly keyProvider: KeyProvider;
  readonly cryptoProvider?: CryptoProvider | null;
  readonly nodeLike?: NodeLike | null;
  readonly supportedSealedAlgorithms?: readonly string[] | null;
  readonly supportedChannelAlgorithms?: readonly string[] | null;
}

type ManagerInstance = EncryptionManager & Partial<NodeEventListener>;

function isNodeEventListenerInstance(
  value: EncryptionManager,
): value is ManagerInstance {
  return (
    typeof (value as Partial<NodeEventListener>).onNodeStarted === "function" ||
    typeof (value as Partial<NodeEventListener>).onNodeAttachToUpstream ===
      "function" ||
    typeof (value as Partial<NodeEventListener>).onNodeStopped === "function"
  );
}

export class CompositeEncryptionManager
  implements EncryptionManager, NodeEventListener
{
  public readonly priority = 1000;

  private secureChannelManager: SecureChannelManager | null;
  private readonly keyProvider: KeyProvider;
  private readonly cryptoProvider: CryptoProvider | null;
  private nodeLike: NodeLike | null;
  private nodeReady = false;
  private lastAttachInfo: AttachInfo | null = null;
  private readonly supportedSealedAlgorithms: readonly string[];
  private readonly supportedChannelAlgorithms: readonly string[];

  private readonly factoryRegistry = getEncryptionManagerFactoryRegistry();
  private readonly managerInstances = new Map<string, EncryptionManager>();

  constructor({
    secureChannelManager = null,
    keyProvider,
    cryptoProvider = null,
    nodeLike = null,
    supportedSealedAlgorithms = DEFAULT_SEALED_ALGORITHMS,
    supportedChannelAlgorithms = DEFAULT_CHANNEL_ALGORITHMS,
  }: CompositeEncryptionManagerDependencies) {
    this.secureChannelManager = secureChannelManager ?? null;
    this.keyProvider = keyProvider;
    this.cryptoProvider = cryptoProvider ?? null;
    this.nodeLike = nodeLike ?? null;
    this.supportedSealedAlgorithms =
      supportedSealedAlgorithms ?? DEFAULT_SEALED_ALGORITHMS;
    this.supportedChannelAlgorithms =
      supportedChannelAlgorithms ?? DEFAULT_CHANNEL_ALGORITHMS;
  }

  public async encryptEnvelope(
    envelope: FameEnvelope,
    opts?: EncryptionOptions,
  ): Promise<EncryptionResult> {
    const manager = await this.getManagerForOptions(opts ?? null);
    if (!manager) {
      return EncryptionResult.skipped(envelope);
    }

    try {
      return await manager.encryptEnvelope(envelope, opts);
    } catch (error) {
      logger.error("composite_encrypt_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return EncryptionResult.skipped(envelope);
    }
  }

  public async decryptEnvelope(
    envelope: FameEnvelope,
    opts?: EncryptionOptions,
  ): Promise<FameEnvelope> {
    const algorithm = envelope.sec?.enc?.alg;
    if (!algorithm) {
      return envelope;
    }

    const manager = await this.getManagerForAlgorithm(algorithm);
    if (!manager) {
      return envelope;
    }

    try {
      return await manager.decryptEnvelope(envelope, opts);
    } catch (error) {
      logger.error("composite_decrypt_failed", {
        algorithm,
        error: error instanceof Error ? error.message : String(error),
      });
      return envelope;
    }
  }

  public async notifyChannelEstablished(channelId: string): Promise<void> {
    const factories = this.factoryRegistry.getFactoriesByType("channel");
    if (factories.length === 0) {
      return;
    }

    logger.debug("composite_notify_channel_established", {
      channel_id: channelId,
    });

    await this.notifyManagers(factories, async (manager, factoryKey) => {
      const channelAware = manager as {
        notifyChannelEstablished?: (channelId: string) => Promise<void> | void;
      };

      if (typeof channelAware.notifyChannelEstablished === "function") {
        await channelAware.notifyChannelEstablished(channelId);
        logger.debug("composite_channel_established_notified", {
          factory: factoryKey,
          channel_id: channelId,
        });
      }
    });
  }

  public async notifyChannelFailed(
    channelId: string,
    reason = "handshake_failed",
  ): Promise<void> {
    const factories = this.factoryRegistry.getFactoriesByType("channel");
    if (factories.length === 0) {
      return;
    }

    logger.debug("composite_notify_channel_failed", {
      channel_id: channelId,
      reason,
    });

    await this.notifyManagers(factories, async (manager, factoryKey) => {
      const channelAware = manager as {
        notifyChannelFailed?: (
          channelId: string,
          reason?: string,
        ) => Promise<void> | void;
      };

      if (typeof channelAware.notifyChannelFailed === "function") {
        await channelAware.notifyChannelFailed(channelId, reason);
        logger.debug("composite_channel_failed_notified", {
          factory: factoryKey,
          channel_id: channelId,
          reason,
        });
      }
    });
  }

  public async notifyKeyAvailable(keyId: string): Promise<void> {
    const factories = this.factoryRegistry.getFactoriesByType("sealed");
    if (factories.length === 0) {
      return;
    }

    logger.debug("composite_notify_key_available", { key_id: keyId });

    await this.notifyManagers(factories, async (manager, factoryKey) => {
      const sealedAware = manager as {
        notifyKeyAvailable?: (keyId: string) => Promise<void> | void;
      };

      if (typeof sealedAware.notifyKeyAvailable === "function") {
        await sealedAware.notifyKeyAvailable(keyId);
        logger.debug("composite_key_available_notified", {
          factory: factoryKey,
          key_id: keyId,
        });
      }
    });
  }

  public async onNodeStarted(node: NodeLike): Promise<void> {
    this.nodeLike = node;
    await this.ensureDefaultManagers();

    await this.notifyNodeListeners(async (listener) => {
      await listener.onNodeStarted?.(node);
    });

    this.nodeReady = true;
  }

  public async onNodeAttachToUpstream(
    node: NodeLike,
    attachInfo: AttachInfo,
  ): Promise<void> {
    this.lastAttachInfo = attachInfo;
    await this.notifyNodeListeners(async (listener) => {
      await listener.onNodeAttachToUpstream?.(node, attachInfo);
    });
  }

  public async onNodeStopped(node: NodeLike): Promise<void> {
    await this.notifyNodeListeners(async (listener) => {
      await listener.onNodeStopped?.(node);
    });

    this.nodeReady = false;
    this.lastAttachInfo = null;
  }

  private async ensureDefaultManagers(): Promise<void> {
    const sealedAlg = this.supportedSealedAlgorithms[0];
    if (sealedAlg) {
      await this.getManagerForAlgorithm(sealedAlg);
    }

    const channelAlg = this.supportedChannelAlgorithms[0];
    if (channelAlg) {
      await this.getManagerForAlgorithm(channelAlg);
    }
  }

  private async getManagerForOptions(
    opts: EncryptionOptions | null,
  ): Promise<EncryptionManager | null> {
    const factory = this.factoryRegistry.getFactoryForOptions(
      opts ?? undefined,
    );
    if (!factory) {
      logger.debug("composite_no_factory_for_options", { opts });
      return null;
    }

    return await this.getOrCreateManager(factory, "options");
  }

  private async getManagerForAlgorithm(
    algorithm: string,
  ): Promise<EncryptionManager | null> {
    const factory = this.factoryRegistry.getFactoryForAlgorithm(algorithm);
    if (!factory) {
      logger.debug("composite_no_factory_for_algorithm", { algorithm });
      return null;
    }

    return await this.getOrCreateManager(factory, algorithm);
  }

  private async getOrCreateManager(
    factory: EncryptionManagerFactory,
    context: string,
  ): Promise<EncryptionManager | null> {
    const key = this.resolveFactoryKey(factory);
    const existing = this.managerInstances.get(key);
    if (existing) {
      return existing;
    }

    try {
      const dependencies: EncryptionFactoryDependencies = {
        keyProvider: this.keyProvider,
        ...(this.secureChannelManager !== null
          ? { secureChannelManager: this.secureChannelManager }
          : {}),
        ...(this.cryptoProvider !== null
          ? { cryptoProvider: this.cryptoProvider }
          : {}),
        ...(this.nodeLike !== null ? { nodeLike: this.nodeLike } : {}),
      };

      const manager = await factory.create(null, dependencies);
      this.managerInstances.set(key, manager);

      await this.applyNodeContext(manager, key);

      logger.debug("composite_created_manager", {
        factory: key,
        context,
        manager_type: manager.constructor.name,
      });

      return manager;
    } catch (error) {
      logger.error("composite_create_manager_failed", {
        factory: key,
        context,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  private async notifyManagers(
    factories: readonly EncryptionManagerFactory[],
    callback: (manager: EncryptionManager, factoryKey: string) => Promise<void>,
  ): Promise<void> {
    for (const factory of factories) {
      const factoryKey = this.resolveFactoryKey(factory);
      const manager = this.managerInstances.get(factoryKey);
      if (!manager) {
        logger.debug("composite_skip_notification_no_manager", {
          factory: factoryKey,
        });
        continue;
      }

      try {
        await callback(manager, factoryKey);
      } catch (error) {
        logger.error("composite_notify_manager_failed", {
          factory: factoryKey,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  private async notifyNodeListeners(
    callback: (listener: ManagerInstance) => Promise<void>,
  ): Promise<void> {
    for (const manager of this.managerInstances.values()) {
      if (!isNodeEventListenerInstance(manager)) {
        continue;
      }

      try {
        await callback(manager);
      } catch (error) {
        logger.error("composite_node_event_failed", {
          manager: manager.constructor.name,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  private async applyNodeContext(
    manager: EncryptionManager,
    factoryKey: string,
  ): Promise<void> {
    if (
      !this.nodeLike ||
      !this.nodeReady ||
      !isNodeEventListenerInstance(manager)
    ) {
      return;
    }

    try {
      await manager.onNodeStarted?.(this.nodeLike);
    } catch (error) {
      logger.error("composite_apply_node_context_failed", {
        stage: "onNodeStarted",
        factory: factoryKey,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    if (!this.lastAttachInfo) {
      return;
    }

    try {
      await manager.onNodeAttachToUpstream?.(
        this.nodeLike,
        this.lastAttachInfo,
      );
    } catch (error) {
      logger.error("composite_apply_node_context_failed", {
        stage: "onNodeAttachToUpstream",
        factory: factoryKey,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private resolveFactoryKey(factory: EncryptionManagerFactory): string {
    return factory.constructor?.name ?? "anonymous-factory";
  }

  /**
   * Clear channel cache for a destination address.
   * Delegates to channel encryption manager instances if available.
   */
  public clearChannelCacheForDestination(destination: string): void {
    const channelFactories = this.factoryRegistry.getFactoriesByType("channel");
    for (const factory of channelFactories) {
      const factoryKey = this.resolveFactoryKey(factory);
      const manager = this.managerInstances.get(factoryKey);
      if (manager) {
        const channelAware = manager as {
          clearChannelCacheForDestination?: (destination: string) => void;
        };
        if (
          typeof channelAware.clearChannelCacheForDestination === "function"
        ) {
          channelAware.clearChannelCacheForDestination(destination);
          logger.debug("composite_cleared_channel_cache", {
            destination,
            factory: factoryKey,
          });
        }
      }
    }
  }

  /**
   * Remove all channels for a destination.
   * Delegates to secure channel manager if available.
   */
  public removeChannelsForDestination(destination: string): number {
    if (!this.secureChannelManager) {
      return 0;
    }

    if (
      typeof this.secureChannelManager.removeChannelsForDestination ===
      "function"
    ) {
      const removed =
        this.secureChannelManager.removeChannelsForDestination(destination);
      if (removed > 0) {
        logger.debug("composite_removed_channels", {
          destination,
          count: removed,
        });
      }
      return removed;
    }

    return 0;
  }
}
