import { HttpBundleProvider } from "./http-bundle-provider.js";
import { createTrustStoreProviderFromEnv } from "./env-provider.js";
import type { HttpBundleProviderOptions } from "./http-bundle-provider.js";
import type { TrustStoreProvider } from "./trust-store-provider.js";
import {
  TRUST_STORE_PROVIDER_FACTORY_BASE_TYPE,
  TrustStoreProviderFactory,
  type TrustStoreProviderConfig,
  type TrustStoreProviderDependencies,
} from "./trust-store-provider-factory.js";

export interface BrowserTrustStoreProviderConfig extends TrustStoreProviderConfig {
  readonly type: "BrowserTrustStoreProvider";
  readonly url?: string | null;
  readonly hashPins?: readonly string[] | null;
  readonly allowedSpkis?: readonly string[] | null;
  readonly allowTofu?: boolean | null;
  readonly refreshIntervalMs?: number | null;
  readonly env?: Record<string, unknown> | null;
  readonly enforcePinsInBrowser?: boolean | null;
}

export const FACTORY_META = {
  base: TRUST_STORE_PROVIDER_FACTORY_BASE_TYPE,
  key: "BrowserTrustStoreProvider",
  isDefault: !isNodeEnvironment(),
  priority: !isNodeEnvironment() ? 100 : 10,
} as const;

export class BrowserTrustStoreProviderFactory extends TrustStoreProviderFactory<BrowserTrustStoreProviderConfig> {
  public readonly type = "BrowserTrustStoreProvider";
  public readonly isDefault = FACTORY_META.isDefault;
  public readonly priority = FACTORY_META.priority;

  public async create(
    config?: BrowserTrustStoreProviderConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<TrustStoreProvider> {
    const normalized = this.normalizeConfig(config);
    const dependencies = this.extractDependencies(factoryArgs);

    if (normalized.url) {
      return this.createHttpProviderFromConfig(normalized);
    }

    const envOverride = normalized.env ?? dependencies?.env ?? null;
    const provider = await createTrustStoreProviderFromEnv({
      env: envOverride ?? undefined,
      requirePinsInBrowser: true,
    });

    if (provider) {
      return provider;
    }

    return this.createUnconfiguredProvider(
      "Trust store is not configured. In browser environments set FAME_CA_CERTS to an HTTPS trust bundle URL or provide an explicit configuration.",
    );
  }

  private createHttpProviderFromConfig(
    config: BrowserTrustStoreProviderConfig,
  ): TrustStoreProvider {
    const url = config.url?.trim();
    if (!url) {
      throw new Error("Browser trust store provider requires a bundle URL");
    }

    if (!/^https:\/\//iu.test(url)) {
      // throw new Error("Trust bundle URL must use HTTPS in browser environments");
    }

    const options: HttpBundleProviderOptions = {
      url,
      hashPins: config.hashPins ?? undefined,
      allowedSpkis: config.allowedSpkis ?? undefined,
      allowTofu: config.allowTofu ?? undefined,
      refreshIntervalMs: config.refreshIntervalMs ?? undefined,
      enforcePinsInBrowser: config.enforcePinsInBrowser ?? true,
    };

    return new HttpBundleProvider(options);
  }

  private normalizeConfig(
    config?: BrowserTrustStoreProviderConfig | Record<string, unknown> | null,
  ): BrowserTrustStoreProviderConfig {
    if (!config) {
      return {
        type: "BrowserTrustStoreProvider",
      };
    }

    if ((config as BrowserTrustStoreProviderConfig).type === "BrowserTrustStoreProvider") {
      return config as BrowserTrustStoreProviderConfig;
    }

    return {
      ...config,
      type: "BrowserTrustStoreProvider",
    } as BrowserTrustStoreProviderConfig;
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

export default BrowserTrustStoreProviderFactory;
