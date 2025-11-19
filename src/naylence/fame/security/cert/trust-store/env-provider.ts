import type {
  DataPemSource,
  FilePemSource,
  HttpsBundleSource,
  InlinePemSource,
  TrustBundleSource,
  TrustAnchor,
  TrustStoreProvider,
} from "@naylence/runtime";
import { HttpBundleProvider } from "./http-bundle-provider.js";
import { parseFameCaCerts } from "./fame-ca-certs-parser.js";
import { anchorsToPem, pemChainToAnchors } from "./anchor-utils.js";
import {
  createProviderFromDataUri,
  createProviderFromPem,
  loadPemFromFile,
} from "./static-bundle-provider.js";

export interface CreateTrustStoreProviderOptions {
  readonly env?: Record<string, unknown> | null;
  readonly requirePinsInBrowser?: boolean;
}

export async function createTrustStoreProviderFromEnv(
  options: CreateTrustStoreProviderOptions = {},
): Promise<TrustStoreProvider | null> {
  const env = resolveEnv(options.env);
  const rawSources = envValue(env, "FAME_CA_CERTS");

  const hashPins = envValue(env, "FAME_CA_BUNDLE_SHA256");
  const allowedSpkis = envValue(env, "FAME_CA_ALLOWED_ROOT_SPKIS");
  const allowTofuRaw = envValue(env, "FAME_CA_ALLOW_TOFU");
  const refreshIntervalRaw = envValue(env, "FAME_CA_REFRESH_INTERVAL_MS");

  const sources = parseFameCaCerts(rawSources, {
    hashPins,
    allowedSpkis,
    allowTofu: toScalar(allowTofuRaw),
    refreshIntervalMs: toScalar(refreshIntervalRaw),
  });

  if (sources.length === 0) {
    return null;
  }

  const providers = await Promise.all(
    sources.map((source) => buildProviderForSource(source, options)),
  );

  if (providers.length === 1) {
    return providers[0] as TrustStoreProvider;
  }

  return new CompositeTrustStoreProvider(providers);
}

class CompositeTrustStoreProvider implements TrustStoreProvider {
  private readonly providers: readonly TrustStoreProvider[];
  private cachedPem: string | null = null;
  private initialized = false;

  public constructor(providers: readonly TrustStoreProvider[]) {
    this.providers = providers;
  }

  public async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }
    for (const provider of this.providers) {
      if (typeof provider.initialize === "function") {
        await provider.initialize();
      }
    }
    this.cachedPem = null;
    this.initialized = true;
  }

  public async getRoots(): Promise<readonly TrustAnchor[]> {
    await this.initializeIfNeeded();
    const rootsLists = await Promise.all(
      this.providers.map((provider) => provider.getRoots()),
    );

    return rootsLists.flat();
  }

  public async getTrustStorePem(): Promise<string> {
    await this.initializeIfNeeded();
    if (this.cachedPem) {
      return this.cachedPem;
    }

    const anchors = [] as TrustAnchor[];
    for (const provider of this.providers) {
      const pem = await provider.getTrustStorePem();
      if (pem.trim().length === 0) {
        continue;
      }
      anchors.push(...pemChainToAnchors(pem));
    }

    const combined = anchorsToPem(anchors);
    if (!combined) {
      throw new Error("Combined trust store bundle is empty");
    }

    this.cachedPem = combined;
    return combined;
  }

  public onUpdate(callback: () => void): () => void {
    const wrapped = () => {
      this.cachedPem = null;
      callback();
    };

    const unsubscribers = this.providers
      .map((provider) => provider.onUpdate?.(wrapped) ?? null)
      .filter((fn): fn is () => void => typeof fn === "function");

    return () => {
      for (const unsubscribe of unsubscribers) {
        try {
          unsubscribe();
        } catch {
          // Swallow cleanup errors
        }
      }
    };
  }

  private async initializeIfNeeded(): Promise<void> {
    if (!this.initialized) {
      await this.initialize();
    }
  }
}

async function buildProviderForSource(
  source: TrustBundleSource,
  options: CreateTrustStoreProviderOptions,
): Promise<TrustStoreProvider> {
  switch (source.type) {
    case "INLINE_PEM":
      return buildInlinePemProvider(source);
    case "DATA_PEM":
      return buildDataUriProvider(source);
    case "FILE":
      return buildFileProvider(source);
    case "HTTPS_BUNDLE":
      return buildHttpProvider(source, options);
    default:
      throw new Error(`Unsupported trust bundle source: ${(source as { type?: string }).type ?? "unknown"}`);
  }
}

function buildInlinePemProvider(source: InlinePemSource): TrustStoreProvider {
  return createProviderFromPem(source.pem);
}

function buildDataUriProvider(source: DataPemSource): TrustStoreProvider {
  return createProviderFromDataUri(source.dataUri);
}

async function buildFileProvider(source: FilePemSource): Promise<TrustStoreProvider> {
  const pem = await loadPemFromFile(source.path);
  return createProviderFromPem(pem);
}

function buildHttpProvider(
  source: HttpsBundleSource,
  options: CreateTrustStoreProviderOptions,
): TrustStoreProvider {
  return new HttpBundleProvider({
    url: source.url,
    hashPins: source.hashPins,
    allowedSpkis: source.allowedSpkis,
    allowTofu: source.allowTofu,
    refreshIntervalMs: source.refreshIntervalMs,
    enforcePinsInBrowser: options.requirePinsInBrowser !== false,
  });
}

function resolveEnv(fallback?: Record<string, unknown> | null): Record<string, unknown> {
  if (fallback && typeof fallback === "object") {
    return fallback;
  }

  if (isNodeEnvironment() && typeof process !== "undefined") {
    return process.env as unknown as Record<string, unknown>;
  }

  if (typeof globalThis === "object" && globalThis) {
    const scoped = globalThis as Record<string, unknown> & {
      __ENV__?: Record<string, unknown>;
      env?: Record<string, unknown>;
    };

    if (scoped.__ENV__ && typeof scoped.__ENV__ === "object") {
      return scoped.__ENV__;
    }

    if (scoped.env && typeof scoped.env === "object") {
      return scoped.env;
    }
  }

  return {};
}

function envValue(
  env: Record<string, unknown>,
  key: string,
): string | string[] | null {
  const direct = env[key];
  if (typeof direct === "string" || Array.isArray(direct)) {
    return direct as string | string[];
  }

  if (typeof process !== "undefined" && process.env?.[key]) {
    return process.env[key] as string;
  }

  return null;
}

function toScalar(value: string | string[] | null): string | null {
  if (Array.isArray(value)) {
    return value.length > 0 ? value[value.length - 1] ?? null : null;
  }
  return value;
}

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions !== "undefined" &&
    typeof process.versions.node === "string"
  );
}
