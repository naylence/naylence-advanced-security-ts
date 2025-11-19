import { sha256 } from "@noble/hashes/sha2.js";
import { getLogger } from "@naylence/runtime";
import type {
  TrustAnchor,
  TrustStoreProvider,
  TrustBundlePins,
} from "@naylence/runtime";

import {
  anchorsToPem,
  computeSpkiSha256,
  normalizePem,
  pemChainToAnchors,
  toBase64Url,
  withComputedSpki,
} from "./anchor-utils.js";

interface CachedBundleEntry {
  anchors: TrustAnchor[];
  etag: string | null;
  fetchedAt: number;
  hash: string | null;
  version: number | null;
}

export interface HttpBundleProviderOptions extends TrustBundlePins {
  readonly url: string;
  readonly cacheKey?: string;
  readonly enforcePinsInBrowser?: boolean;
  readonly allowInsecureHttp?: boolean;
}

const DEFAULT_REFRESH_INTERVAL_MS = 86_400_000; // 24 hours
const MIN_REFRESH_INTERVAL_MS = 60_000; // 1 minute

const logger = getLogger("naylence.fame.security.cert.trust_store.http_bundle_provider");

function isTruthyFlag(value: unknown): boolean {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (!normalized) {
      return false;
    }

    return normalized !== "false" && normalized !== "0";
  }

  return false;
}

function isCacheDisabled(): boolean {
  if (isNodeEnvironment() && typeof process !== "undefined") {
    const flag = process.env?.NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE;
    if (flag !== undefined) {
      return isTruthyFlag(flag);
    }
  }

  if (typeof globalThis !== "undefined") {
    const globalFlag = (globalThis as {
      NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE?: unknown;
    }).NAYLENCE_TRUST_BUNDLE_DISABLE_CACHE;

    if (globalFlag !== undefined) {
      return isTruthyFlag(globalFlag);
    }
  }

  return false;
}

export class HttpBundleProvider implements TrustStoreProvider {
  private readonly url: URL;
  private readonly refreshIntervalMs: number;
  private readonly hashPins: readonly string[];
  private readonly allowedSpkis: readonly string[];
  private readonly allowTofu: boolean;
  private readonly enforceBrowserPins: boolean;
  private readonly cacheKey: string;
  private readonly allowInsecureHttp: boolean;

  private lastFetched = 0;
  private etag: string | null = null;
  private lastKnownHash: string | null = null;
  private version: number | null = null;
  private anchors: TrustAnchor[] | null = null;
  private inflight: Promise<TrustAnchor[]> | null = null;
  private readonly listeners = new Set<() => void>();
  private initialized = false;
  private pemChain: string | null = null;

  public constructor(options: HttpBundleProviderOptions) {
    if (!options.url) {
      throw new Error("HTTP trust bundle requires a URL");
    }

    const parsed = new URL(options.url);
    const allowInsecureEnv = isTruthyFlag(
      getGlobalFlag("FAME_TRUST_BUNDLE_ALLOW_HTTP"),
    );
    const allowInsecureOption = options.allowInsecureHttp === true;
    this.allowInsecureHttp = allowInsecureEnv || allowInsecureOption;

    if (parsed.protocol !== "https:") {
      const isLoopbackHost = isLoopbackHostname(parsed.hostname);
      const devMode = !isProductionEnvironment();

      if (!(this.allowInsecureHttp && devMode && isLoopbackHost)) {
        throw new Error(
          "Trust bundle URL must use HTTPS (set allowInsecureHttp or FAME_TRUST_BUNDLE_ALLOW_HTTP for dev-only http)",
        );
      }

      logger.warning("allowing_insecure_trust_bundle_url", {
        url: parsed.toString(),
        devMode,
        isLoopbackHost,
      });
    }

    this.url = parsed;
    this.refreshIntervalMs = normalizeRefreshInterval(
      options.refreshIntervalMs,
    );
    this.hashPins = normalizeHashPins(options.hashPins);
    this.allowedSpkis = normalizeAllowedSpkis(options.allowedSpkis);
    this.allowTofu = options.allowTofu === true;
    this.enforceBrowserPins = options.enforcePinsInBrowser !== false;
    this.cacheKey =
      options.cacheKey ?? computeCacheKey(`${parsed.origin}${parsed.pathname}`);

    if (isBrowserEnvironment() && !this.allowTofu && this.enforceBrowserPins) {
      if (this.hashPins.length === 0 && this.allowedSpkis.length === 0) {
        throw new Error(
          "Browser environments require hash pin, SPKI allowlist, or TOFU",
        );
      }
    }
  }

  public async getRoots(): Promise<readonly TrustAnchor[]> {
    if (!this.initialized) {
      await this.initialize();
    }

    if (this.inflight) {
      return this.inflight;
    }

    const now = Date.now();
    const stale = now - this.lastFetched >= this.refreshIntervalMs;
    if (stale || !this.anchors) {
      this.inflight = this.fetchLatest()
        .catch((error) => {
          logger.warning("trust_bundle_refresh_failed", {
            error: error instanceof Error ? error.message : String(error),
          });
          if (this.anchors) {
            return this.anchors;
          }
          throw error;
        })
        .finally(() => {
          this.inflight = null;
        });
      return this.inflight;
    }

    return this.anchors;
  }

  public async getTrustStorePem(): Promise<string> {
    const anchors = await this.getRoots();
    if (!anchors || anchors.length === 0) {
      throw new Error("Trust bundle does not contain any certificates");
    }

    if (!this.pemChain || this.pemChain.trim().length === 0) {
      this.pemChain = anchorsToPem(anchors);
    }

    if (!this.pemChain) {
      throw new Error("Trust bundle PEM resolution failed");
    }

    return this.pemChain;
  }

  public onUpdate(callback: () => void): () => void {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  }

  public async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }
    try {
      const cached = await loadCache(this.cacheKey);
      if (cached) {
        this.applyCachedEntry(cached);
        logger.debug("loaded_trust_bundle_from_cache", {
          url: this.url.href,
          anchorCount: cached.anchors.length,
        });
      }
    } catch (error) {
      logger.warning("failed_to_load_cached_trust_bundle", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
    this.initialized = true;
  }

  private applyCachedEntry(entry: CachedBundleEntry): void {
    this.anchors = withComputedSpki(entry.anchors);
    this.etag = entry.etag;
    this.lastFetched = entry.fetchedAt;
    this.lastKnownHash = entry.hash;
    this.version = entry.version;
    this.pemChain = this.anchors ? anchorsToPem(this.anchors) : null;
  }

  private async fetchLatest(): Promise<TrustAnchor[]> {
    const headers: Record<string, string> = {
      "Accept": "application/json, application/pem-certificate-chain, text/plain",
    };

    if (this.etag) {
      headers["If-None-Match"] = this.etag;
    }

    const response = await fetch(this.url, {
      method: "GET",
      headers,
      cache: "no-store",
    });

    if (response.status === 304 && this.anchors) {
      this.lastFetched = Date.now();
      return this.anchors;
    }

    if (!response.ok) {
      throw new Error(
        `Failed to download trust bundle: ${response.status} ${response.statusText}`,
      );
    }

    const arrayBuffer = await response.arrayBuffer();
    const payload = new Uint8Array(arrayBuffer);
    const hash = computeHash(payload);

    const pins = this.hashPins.length > 0 ? this.hashPins : null;
    if (pins && !pins.includes(hash)) {
      throw new Error("Trust bundle hash mismatch");
    }

    let expectedHash = pins ? hash : null;
    if (!pins) {
      if (this.lastKnownHash) {
        if (this.lastKnownHash !== hash) {
          throw new Error("Trust bundle hash changed without pin");
        }
        expectedHash = hash;
      } else if (this.allowTofu) {
        expectedHash = hash;
      } else if (isBrowserEnvironment() && this.enforceBrowserPins) {
        throw new Error("Browser download without pins or TOFU is blocked");
      }
    }

    const bundle = parseBundlePayload(payload, this.url.href);

    if (bundle.version !== null && this.version !== null) {
      if (bundle.version < this.version) {
        throw new Error("Trust bundle downgrade detected");
      }
    }

    if (this.allowedSpkis.length > 0) {
      enforceSpkiAllowlist(bundle.anchors, this.allowedSpkis);
    }

    const etagHeader = response.headers.get("etag");
    this.anchors = withComputedSpki(bundle.anchors);
    this.etag = etagHeader;
    this.lastFetched = Date.now();
    this.lastKnownHash = expectedHash;
    this.version = bundle.version;
    this.pemChain = anchorsToPem(this.anchors);

    const cacheEntry: CachedBundleEntry = {
      anchors: this.anchors,
      etag: this.etag,
      fetchedAt: this.lastFetched,
      hash: this.lastKnownHash,
      version: this.version,
    };

    await saveCache(this.cacheKey, cacheEntry);
    this.notifyListeners();
    return this.anchors;
  }

  private notifyListeners(): void {
    for (const callback of this.listeners) {
      try {
        callback();
      } catch (error) {
        logger.warning("trust_bundle_listener_failed", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
}

function getGlobalFlag(name: string): unknown {
  if (typeof process !== "undefined" && process.env) {
    const envValue = process.env[name];
    if (envValue !== undefined) {
      return envValue;
    }
  }

  if (typeof globalThis !== "undefined") {
    return (globalThis as Record<string, unknown>)[name];
  }

  return undefined;
}

function isLoopbackHostname(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "[::1]") {
    return true;
  }

  if (/^127(?:\.\d{1,3}){3}$/.test(hostname)) {
    return true;
  }

  return false;
}

interface ParsedBundle {
  anchors: TrustAnchor[];
  version: number | null;
}

function parseBundlePayload(
  payload: Uint8Array,
  sourceUrl: string,
): ParsedBundle {
  const text = bytesToUtf8(payload);
  const trimmed = text.trim();

  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    const version = typeof parsed.version === "number" ? parsed.version : null;
    const roots = Array.isArray(parsed.roots) ? parsed.roots : [];

    const anchors: TrustAnchor[] = roots
      .map((root) => {
        const record = root as Record<string, unknown>;
        const pem = normalizePem(String(record.pem ?? ""));
        if (!pem) {
          return null;
        }

        const anchor: TrustAnchor = {
          pem,
          ...(typeof record.kid === "string" ? { kid: record.kid } : {}),
          ...(typeof record.validUntil === "string"
            ? { notAfter: record.validUntil }
            : {}),
          ...(typeof record.notBefore === "string"
            ? { notBefore: record.notBefore }
            : {}),
        };

        return anchor;
      })
      .filter((anchor): anchor is TrustAnchor => anchor !== null);

    if (anchors.length === 0) {
      throw new Error("Trust bundle JSON does not contain any roots");
    }

    return { anchors, version };
  }

  if (trimmed.includes("-----BEGIN")) {
    return { anchors: pemChainToAnchors(trimmed), version: null };
  }

  throw new Error(`Unsupported trust bundle format from ${sourceUrl}`);
}

function enforceSpkiAllowlist(
  anchors: readonly TrustAnchor[],
  allowlist: readonly string[],
): void {
  const missing = [] as string[];
  for (const anchor of anchors) {
    const spki = anchor.spkiSha256 ?? computeSpkiSha256(anchor.pem);
    if (!spki || !allowlist.includes(spki)) {
      missing.push(anchor.kid ?? spki ?? "unknown");
    }
  }

  if (missing.length > 0) {
    throw new Error(
      `Trust bundle contains roots not present in SPKI allowlist: ${missing.join(",")}`,
    );
  }
}

function normalizeHashPins(
  pins: readonly string[] | undefined,
): readonly string[] {
  if (!pins || pins.length === 0) {
    return [];
  }

  return pins
    .map((pin) => pin.trim())
    .filter((pin) => pin.length > 0)
    .map((pin) => {
      if (/^[0-9a-fA-F]{64}$/u.test(pin)) {
        return hexToBase64Url(pin);
      }
      return pin;
    });
}

function normalizeAllowedSpkis(
  entries: readonly string[] | undefined,
): readonly string[] {
  if (!entries || entries.length === 0) {
    return [];
  }
  return entries.map((entry) => entry.trim()).filter((entry) => entry.length);
}

function normalizeRefreshInterval(value?: number): number {
  if (typeof value !== "number" || Number.isNaN(value) || value <= 0) {
    return DEFAULT_REFRESH_INTERVAL_MS;
  }
  return Math.max(MIN_REFRESH_INTERVAL_MS, Math.floor(value));
}

function computeHash(payload: Uint8Array): string {
  const digest = sha256(payload);
  return toBase64Url(digest);
}

function hexToBase64Url(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return toBase64Url(bytes);
}

function bytesToUtf8(data: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(data);
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("utf8");
  }
  return String.fromCharCode(...Array.from(data));
}

function computeCacheKey(value: string): string {
  const digest = sha256(new TextEncoder().encode(value));
  return Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function loadCache(key: string): Promise<CachedBundleEntry | null> {
  if (isCacheDisabled()) {
    return null;
  }
  if (isNodeEnvironment()) {
    return loadCacheFromFile(key);
  }
  return loadCacheFromBrowser(key);
}

async function saveCache(key: string, entry: CachedBundleEntry): Promise<void> {
  if (isCacheDisabled()) {
    return;
  }
  if (isNodeEnvironment()) {
    await saveCacheToFile(key, entry);
  } else {
    await saveCacheToBrowser(key, entry);
  }
}

async function loadCacheFromFile(key: string): Promise<CachedBundleEntry | null> {
  try {
    const { default: path } = await import("node:path");
    const fs = await import("node:fs/promises");
    const os = await import("node:os");

    const dir = path.join(os.homedir(), ".naylence", "trust-bundles");
    const filePath = path.join(dir, `${key}.json`);
    const content = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(content) as CachedBundleEntry;
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

async function saveCacheToFile(key: string, entry: CachedBundleEntry): Promise<void> {
  const { default: path } = await import("node:path");
  const fs = await import("node:fs/promises");
  const os = await import("node:os");

  const dir = path.join(os.homedir(), ".naylence", "trust-bundles");
  await fs.mkdir(dir, { recursive: true });
  const filePath = path.join(dir, `${key}.json`);
  const payload = JSON.stringify(entry, null, 2);
  await fs.writeFile(filePath, payload, "utf8");
}

const BROWSER_CACHE_NAMESPACE = "naylence.trustBundles";

async function loadCacheFromBrowser(key: string): Promise<CachedBundleEntry | null> {
  const store = await openBrowserStore();
  if (!store) {
    return null;
  }

  return store.get(key);
}

async function saveCacheToBrowser(key: string, entry: CachedBundleEntry): Promise<void> {
  const store = await openBrowserStore();
  if (!store) {
    return;
  }

  await store.set(key, entry);
}

interface BrowserStore {
  get(key: string): Promise<CachedBundleEntry | null>;
  set(key: string, value: CachedBundleEntry): Promise<void>;
}

async function openBrowserStore(): Promise<BrowserStore | null> {
  if (typeof indexedDB !== "undefined") {
    return openIndexedDbStore();
  }

  if (typeof localStorage !== "undefined") {
    return {
      async get(key: string): Promise<CachedBundleEntry | null> {
        const payload = localStorage.getItem(`${BROWSER_CACHE_NAMESPACE}:${key}`);
        if (!payload) {
          return null;
        }
        return JSON.parse(payload) as CachedBundleEntry;
      },
      async set(key: string, value: CachedBundleEntry): Promise<void> {
        localStorage.setItem(
          `${BROWSER_CACHE_NAMESPACE}:${key}`,
          JSON.stringify(value),
        );
      },
    };
  }

  return null;
}

async function openIndexedDbStore(): Promise<BrowserStore | null> {
  return new Promise((resolve) => {
    const request = indexedDB.open("naylence_trust_bundles", 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("bundles")) {
        db.createObjectStore("bundles");
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      resolve({
        get: (key: string) =>
          new Promise<CachedBundleEntry | null>((storeResolve, storeReject) => {
            const transaction = db.transaction("bundles", "readonly");
            const store = transaction.objectStore("bundles");
            const getRequest = store.get(key);
            getRequest.onsuccess = () => {
              storeResolve((getRequest.result as CachedBundleEntry) ?? null);
            };
            getRequest.onerror = () => {
              storeReject(getRequest.error ?? new Error("IndexedDB get failed"));
            };
          }),
        set: (key: string, value: CachedBundleEntry) =>
          new Promise<void>((storeResolve, storeReject) => {
            const transaction = db.transaction("bundles", "readwrite");
            const store = transaction.objectStore("bundles");
            const putRequest = store.put(value, key);
            putRequest.onsuccess = () => {
              storeResolve();
            };
            putRequest.onerror = () => {
              storeReject(putRequest.error ?? new Error("IndexedDB put failed"));
            };
          }),
      });
    };

    request.onerror = () => {
      logger.warning("indexeddb_unavailable_for_trust_bundle_caching", {
        error: request.error ? String(request.error) : "unknown",
      });
      resolve(null);
    };
  });
}

function isBrowserEnvironment(): boolean {
  return typeof window !== "undefined" && typeof window.document !== "undefined";
}

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions !== "undefined" &&
    typeof process.versions.node === "string"
  );
}

function isProductionEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.env !== "undefined" &&
    process.env.NODE_ENV === "production"
  );
}
