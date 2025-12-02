import type { TrustStoreProvider } from "./trust-store-provider.js";
import {
  TRUST_STORE_PROVIDER_FACTORY_BASE_TYPE,
  TrustStoreProviderFactory,
  type TrustStoreProviderConfig,
  type TrustStoreProviderDependencies,
} from "./trust-store-provider-factory.js";
import { createTrustStoreProviderFromEnv } from "./env-provider.js";

export interface EnvTrustStoreProviderConfig extends TrustStoreProviderConfig {
  readonly type: "EnvTrustStoreProvider";
  readonly env?: Record<string, unknown> | null;
  readonly requirePinsInBrowser?: boolean;
}

export const FACTORY_META = {
  base: TRUST_STORE_PROVIDER_FACTORY_BASE_TYPE,
  key: "EnvTrustStoreProvider",
  isDefault: isNodeEnvironment(),
  priority: isNodeEnvironment() ? 100 : 0,
} as const;

export class EnvTrustStoreProviderFactory extends TrustStoreProviderFactory<EnvTrustStoreProviderConfig> {
  public readonly type = "EnvTrustStoreProvider";
  public readonly isDefault = FACTORY_META.isDefault;
  public readonly priority = FACTORY_META.priority;

  public async create(
    config?: EnvTrustStoreProviderConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<TrustStoreProvider> {
    const normalizedConfig = this.normalizeConfig(config);
    const dependencies = this.extractDependencies(factoryArgs);

    const envOverride = normalizedConfig.env ?? dependencies?.env ?? null;
    const requirePinsInBrowser = normalizedConfig.requirePinsInBrowser ?? false;

    const provider = await createTrustStoreProviderFromEnv({
      env: envOverride ?? undefined,
      requirePinsInBrowser,
    });

    if (provider) {
      return provider;
    }

    return this.createUnconfiguredProvider(
      "Trust store is not configured. For Node.js, set FAME_CA_CERTS to a PEM string, a file path, a data URI, or an HTTPS URL.",
    );
  }

  private normalizeConfig(
    config?: EnvTrustStoreProviderConfig | Record<string, unknown> | null,
  ): EnvTrustStoreProviderConfig {
    if (!config) {
      return {
        type: "EnvTrustStoreProvider",
      };
    }

    if ((config as EnvTrustStoreProviderConfig).type === "EnvTrustStoreProvider") {
      return config as EnvTrustStoreProviderConfig;
    }

    return {
      ...config,
      type: "EnvTrustStoreProvider",
    } as EnvTrustStoreProviderConfig;
  }

  private extractDependencies(
    factoryArgs: readonly unknown[],
  ): TrustStoreProviderDependencies | null {
    if (factoryArgs.length === 0) {
      return null;
    }

    const candidate = factoryArgs[0];
    if (candidate && typeof candidate === "object") {
      return candidate as TrustStoreProviderDependencies;
    }

    return null;
  }
}

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions !== "undefined" &&
    typeof process.versions.node === "string"
  );
}

export default EnvTrustStoreProviderFactory;
