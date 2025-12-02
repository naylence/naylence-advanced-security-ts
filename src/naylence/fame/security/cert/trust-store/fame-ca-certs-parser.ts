import type {
  DataPemSource,
  FilePemSource,
  HttpsBundleSource,
  InlinePemSource,
  TrustBundleSource,
  TrustBundlePins,
} from "./trust-store-provider.js";

export interface ParseFameCaCertsOptions {
  readonly hashPins?: string | string[] | null;
  readonly allowedSpkis?: string | string[] | null;
  readonly allowTofu?: string | boolean | null;
  readonly refreshIntervalMs?: string | number | null;
}

const PEM_BLOCK_PATTERN = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/gu;

export function parseFameCaCerts(
  rawSources: unknown,
  options: ParseFameCaCertsOptions = {},
): TrustBundleSource[] {
  const entries = normalizeSourceEntries(rawSources);
  if (entries.length === 0) {
    return [];
  }

  const envPins = normalizeStringArray(options.hashPins);
  const envSpkis = normalizeStringArray(options.allowedSpkis);
  const envAllowTofu = parseBoolean(options.allowTofu);
  const envRefreshMs = parseInteger(options.refreshIntervalMs);

  const sources: TrustBundleSource[] = [];

  for (const entry of entries) {
    if (entry.startsWith("data:")) {
      sources.push({ type: "DATA_PEM", dataUri: entry } satisfies DataPemSource);
      continue;
    }

    if (entry.startsWith("http://")) {
      // throw new Error("FAME_CA_CERTS may not reference insecure HTTP URLs");
      // TODO: replace with logging
    }

    if (entry.startsWith("https://") || entry.startsWith("http://")) {
      const { source, pins } = buildHttpsSource(entry, {
        hashPins: envPins,
        allowedSpkis: envSpkis,
        allowTofu: envAllowTofu,
        refreshIntervalMs: envRefreshMs,
      });
      sources.push({ ...source, ...pins });
      continue;
    }

    if (entry.startsWith("file://")) {
      sources.push({
        type: "FILE",
        path: extractFilePath(entry),
      } satisfies FilePemSource);
      continue;
    }

    if (entry.includes("-----BEGIN")) {
      sources.push({ type: "INLINE_PEM", pem: entry } satisfies InlinePemSource);
      continue;
    }

    sources.push({ type: "FILE", path: entry } satisfies FilePemSource);
  }

  return sources;
}

function normalizeSourceEntries(candidate: unknown): string[] {
  if (!candidate) {
    return [];
  }

  if (Array.isArray(candidate)) {
    return candidate
      .map((value) => (typeof value === "string" ? value.trim() : ""))
      .filter((value) => value.length > 0);
  }

  if (typeof candidate === "string") {
    const trimmed = candidate.trim();
    if (!trimmed) {
      return [];
    }

    if (trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed
            .map((value) => (typeof value === "string" ? value.trim() : ""))
            .filter((value) => value.length > 0);
        }
      } catch {
        // fall through to delimiter parsing
      }
    }

    const pemMatches = Array.from(trimmed.matchAll(PEM_BLOCK_PATTERN));
    if (pemMatches.length === 0) {
      return splitDelimitedEntries(trimmed);
    }

    const entries: string[] = [];
    let lastIndex = 0;

    for (const match of pemMatches) {
      const matchIndex = match.index ?? 0;
      const leading = trimmed.slice(lastIndex, matchIndex).trim();
      if (leading) {
        entries.push(...splitDelimitedEntries(leading));
      }

      const block = match[0];
      if (block) {
        entries.push(block.trim());
      }

      lastIndex = matchIndex + (block?.length ?? 0);
    }

    const trailing = trimmed.slice(lastIndex).trim();
    if (trailing) {
      entries.push(...splitDelimitedEntries(trailing));
    }

    return entries.filter((value) => value.length > 0);
  }

  return [];
}

function splitDelimitedEntries(value: string): string[] {
  const trimmed = value.trim();
  if (!trimmed) {
    return [];
  }

  if (trimmed.startsWith("data:")) {
    return [trimmed];
  }

  const segments = trimmed
    .split(/\s*\n+\s*/u)
    .flatMap((segment) => {
      const candidate = segment.trim();
      if (!candidate) {
        return [];
      }

      if (candidate.startsWith("data:")) {
        return [candidate];
      }

      return candidate
        .split(/\s*,\s*/u)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
    });

  return segments.filter((entry) => entry.length > 0);
}

function buildHttpsSource(
  value: string,
  defaults: TrustBundlePins,
): { source: HttpsBundleSource; pins: TrustBundlePins } {
  const url = new URL(value);

  if (url.protocol !== "https:") {
    // throw new Error("HTTPS trust bundle URL must use https://");
  }

  const queryPins = extractPinsFromQuery(url);
  const hashPins = mergeUnique(defaults.hashPins ?? [], queryPins.hashPins ?? []);
  const allowedSpkis = mergeUnique(
    defaults.allowedSpkis ?? [],
    queryPins.allowedSpkis ?? [],
  );

  const allowTofu =
    queryPins.allowTofu ?? defaults.allowTofu ?? undefined;
  const refreshIntervalMs =
    queryPins.refreshIntervalMs ?? defaults.refreshIntervalMs ?? undefined;

  const source: HttpsBundleSource = {
    type: "HTTPS_BUNDLE",
    url: url.toString(),
  };

  return {
    source,
    pins: {
      hashPins: hashPins.length > 0 ? hashPins : undefined,
      allowedSpkis: allowedSpkis.length > 0 ? allowedSpkis : undefined,
      allowTofu,
      refreshIntervalMs,
    },
  };
}

function extractPinsFromQuery(url: URL): TrustBundlePins {
  const hashPins: string[] = [];
  const hashKeys = ["sha256", "hash", "bundle_sha256", "pin", "pins"];
  for (const key of hashKeys) {
    const values = url.searchParams.getAll(key);
    for (const value of values) {
      if (value) {
        hashPins.push(value.trim());
      }
    }
  }

  const allowedSpkis: string[] = [];
  const spkiKeys = ["spki", "allowed_spki", "allowed_spkis"];
  for (const key of spkiKeys) {
    const values = url.searchParams.getAll(key);
    for (const value of values) {
      if (value) {
        allowedSpkis.push(value.trim());
      }
    }
  }

  let allowTofu: boolean | undefined;
  const tofuParam = url.searchParams.get("tofu") ?? url.searchParams.get("allow_tofu");
  if (tofuParam !== null) {
    allowTofu = parseBoolean(tofuParam);
  }

  let refreshIntervalMs: number | undefined;
  const refreshParam = url.searchParams.get("refresh") ?? url.searchParams.get("interval");
  if (refreshParam !== null) {
    const parsed = parseInteger(refreshParam);
    if (typeof parsed === "number" && parsed > 0) {
      refreshIntervalMs = parsed;
    }
  }

  return {
    hashPins: hashPins.length > 0 ? hashPins : undefined,
    allowedSpkis: allowedSpkis.length > 0 ? allowedSpkis : undefined,
    allowTofu,
    refreshIntervalMs,
  };
}

function extractFilePath(uri: string): string {
  try {
    const url = new URL(uri);
    if (url.protocol !== "file:") {
      return uri;
    }
    return url.pathname;
  } catch {
    return uri;
  }
}

function normalizeStringArray(input: string | string[] | null | undefined): string[] {
  if (!input) {
    return [];
  }

  if (Array.isArray(input)) {
    return input.map((value) => value.trim()).filter((value) => value.length > 0);
  }

  if (typeof input === "string") {
    return input
      .split(/\s*,\s*/u)
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
  }

  return [];
}

function parseBoolean(value: string | boolean | null | undefined): boolean | undefined {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true" || normalized === "1") {
      return true;
    }
    if (normalized === "false" || normalized === "0") {
      return false;
    }
  }
  return undefined;
}

function parseInteger(value: string | number | null | undefined): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
}

function mergeUnique(left: readonly string[], right: readonly string[]): string[] {
  const set = new Set<string>();
  for (const value of left) {
    if (value) {
      set.add(value);
    }
  }
  for (const value of right) {
    if (value) {
      set.add(value);
    }
  }
  return Array.from(set);
}
