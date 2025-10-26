import { ExtensionManager } from "@naylence/factory";
import {
  ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  type EncryptionManagerFactory,
} from "@naylence/runtime";
import type { EncryptionOptions } from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";

type EncryptionFactoryInfo = {
  readonly totalFactories: number;
  readonly autoDiscovered: boolean;
  readonly algorithmMappings: Record<string, string>;
  readonly typeMappings: Record<string, string[]>;
};

const logger = getLogger(
  "naylence.fame.security.encryption.encryption_manager_registry",
);

export class EncryptionManagerFactoryRegistry {
  private readonly factories: EncryptionManagerFactory[] = [];
  private readonly algorithmToFactory = new Map<
    string,
    EncryptionManagerFactory
  >();
  private readonly typeToFactories = new Map<
    string,
    EncryptionManagerFactory[]
  >();
  private readonly factorySet = new Set<EncryptionManagerFactory>();
  private readonly autoDiscoveredFactories =
    new Set<EncryptionManagerFactory>();
  private autoDiscovered = false;

  constructor(autoDiscover: boolean = true) {
    if (autoDiscover) {
      this.autoDiscoverFactories();
    }
  }

  private autoDiscoverFactories(): void {
    if (this.autoDiscovered) {
      return;
    }

    try {
      const extensionInfos = ExtensionManager.getExtensionsByType(
        ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
      );

      let registeredCount = 0;
      for (const [factoryName, info] of extensionInfos) {
        if (factoryName === "CompositeEncryptionManager") {
          logger.debug(
            "skipping_composite_factory_to_avoid_circular_dependency",
            {
              factory_name: factoryName,
            },
          );
          continue;
        }

        try {
          const factoryInstance = (info.instance ??
            ExtensionManager.getGlobalFactory(
              ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
              factoryName,
            )) as EncryptionManagerFactory;

          this.registerFactory(factoryInstance, { autoDiscovered: true });
          registeredCount += 1;

          logger.debug("auto_discovered_factory", {
            factory_name: factoryName,
            factory_class: factoryInstance.constructor.name,
            algorithms: factoryInstance.getSupportedAlgorithms(),
            encryption_type: factoryInstance.getEncryptionType(),
            priority: factoryInstance.getPriority(),
          });
        } catch (error) {
          logger.warning("failed_to_auto_register_factory", {
            factory_name: factoryName,
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }

      this.autoDiscovered = true;
      logger.debug("completed_auto_discovery", {
        registered_factories: registeredCount,
        total_discovered: extensionInfos.size,
        skipped_composite: true,
      });
    } catch (error) {
      logger.warning("failed_auto_discovery_of_factories", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  public registerFactory(
    factory: EncryptionManagerFactory,
    options: { autoDiscovered?: boolean } = {},
  ): void {
    if (this.factorySet.has(factory)) {
      return;
    }

    this.factorySet.add(factory);
    this.factories.push(factory);
    if (options.autoDiscovered) {
      this.autoDiscoveredFactories.add(factory);
    }

    for (const algorithm of factory.getSupportedAlgorithms()) {
      const existing = this.algorithmToFactory.get(algorithm);
      if (!existing || factory.getPriority() > existing.getPriority()) {
        this.algorithmToFactory.set(algorithm, factory);
        logger.debug("registered_algorithm_mapping", {
          algorithm,
          factory: factory.constructor.name,
          priority: factory.getPriority(),
        });
      }
    }

    const encryptionType = factory.getEncryptionType();
    const typeFactories = this.typeToFactories.get(encryptionType) ?? [];
    typeFactories.push(factory);
    typeFactories.sort((a, b) => b.getPriority() - a.getPriority());
    this.typeToFactories.set(encryptionType, typeFactories);

    logger.debug("registered_encryption_manager_factory", {
      factory: factory.constructor.name,
      encryption_type: encryptionType,
      algorithms: factory.getSupportedAlgorithms(),
      priority: factory.getPriority(),
      auto_discovered: options.autoDiscovered ?? false,
    });
  }

  public getFactoryForAlgorithm(
    algorithm: string,
  ): EncryptionManagerFactory | undefined {
    this.ensureAutoDiscovery();
    return this.algorithmToFactory.get(algorithm);
  }

  public getFactoryForOptions(
    opts?: EncryptionOptions | null,
  ): EncryptionManagerFactory | undefined {
    this.ensureAutoDiscovery();
    for (const factory of this.factories) {
      if (factory.supportsOptions(opts ?? undefined)) {
        logger.debug("found_factory_for_options", {
          factory: factory.constructor.name,
          encryption_type: factory.getEncryptionType(),
        });
        return factory;
      }
    }

    logger.debug("no_factory_found_for_options", { opts });
    return undefined;
  }

  public getFactoriesByType(
    encryptionType: string,
  ): readonly EncryptionManagerFactory[] {
    this.ensureAutoDiscovery();
    return this.typeToFactories.get(encryptionType) ?? [];
  }

  public getAllSupportedAlgorithms(): readonly string[] {
    this.ensureAutoDiscovery();
    return Array.from(this.algorithmToFactory.keys());
  }

  public getRegistryInfo(): EncryptionFactoryInfo {
    return {
      totalFactories: this.factories.length,
      autoDiscovered: this.autoDiscovered,
      algorithmMappings: Object.fromEntries(
        Array.from(this.algorithmToFactory.entries()).map(
          ([algorithm, factory]) => [algorithm, factory.constructor.name],
        ),
      ),
      typeMappings: Object.fromEntries(
        Array.from(this.typeToFactories.entries()).map(
          ([encType, factories]) => [
            encType,
            factories.map((factory) => factory.constructor.name),
          ],
        ),
      ),
    };
  }

  public forceRediscovery(): void {
    const manualFactories = this.factories.filter(
      (factory) => !this.autoDiscoveredFactories.has(factory),
    );

    this.autoDiscovered = false;
    this.algorithmToFactory.clear();
    this.typeToFactories.clear();
    this.factories.length = 0;
    this.factorySet.clear();
    this.autoDiscoveredFactories.clear();

    for (const factory of manualFactories) {
      this.registerFactory(factory);
    }

    this.autoDiscoverFactories();
  }

  public isAutoDiscovered(): boolean {
    return this.autoDiscovered;
  }

  public ensureInitialized(): void {
    this.ensureAutoDiscovery();
  }

  private ensureAutoDiscovery(): void {
    if (!this.autoDiscovered) {
      this.autoDiscoverFactories();
    }
  }
}

const globalRegistry = new EncryptionManagerFactoryRegistry(true);

export function getEncryptionManagerFactoryRegistry(): EncryptionManagerFactoryRegistry {
  globalRegistry.ensureInitialized();
  return globalRegistry;
}

export function registerEncryptionManagerFactory(
  factory: EncryptionManagerFactory,
): void {
  globalRegistry.registerFactory(factory);
}
