import type { ResourceFactory } from "@naylence/factory";
import { Registry } from "@naylence/factory";

import {
  MODULES,
  MODULE_LOADERS,
  type FactoryModuleLoader,
  type FactoryModuleSpec,
} from "../factory-manifest.js";
import { getEncryptionManagerFactoryRegistry } from "./encryption/encryption-manager-registry.js";

type FactoryRegistrar = Pick<typeof Registry, "registerFactory">;

type FactoryConstructor = new (
  ...args: unknown[]
) => ResourceFactory<unknown, unknown>;

type FactoryMetadata = {
  readonly base?: string;
  readonly key?: string;
  readonly [key: string]: unknown;
};

type DynamicImporter = (specifier: string) => Promise<unknown>;

const SECURITY_PREFIX = "./security/" as const;
const SECURITY_MODULES = MODULES.filter((spec) =>
  spec.startsWith(SECURITY_PREFIX),
);
const EXTRA_MODULES = MODULES.filter(
  (spec) => !spec.startsWith(SECURITY_PREFIX),
);

const NODE_ONLY_MODULES = new Set<FactoryModuleSpec>([
  "./security/cert/default-ca-service-factory.js",
  "./security/cert/trust-store/node-trust-store-provider-factory.js",
]);

const FACTORY_MODULE_PREFIX =
  "@naylence/advanced-security/naylence/fame/" as const;
const BROWSER_DIST_SEGMENT = "/dist/browser/" as const;

function detectModuleUrl(): string | null {
  if (typeof __filename === "string") {
    try {
      return __filename.startsWith("file://")
        ? __filename
        : `file://${__filename}`;
    } catch {
      // fall through to stack parsing
    }
  }

  try {
    throw new Error();
  } catch (error) {
    const stack =
      typeof error === "object" && error && "stack" in error
        ? String((error as Error).stack ?? "")
        : "";

    const lines = stack.split("\n");
    for (const line of lines) {
      const match = line.match(
        /(https?:\/\/[^\s)]+|file:\/\/[^\s)]+\.(?:js|ts)|\/(?:[^\s)]+\.(?:js|ts)))/u,
      );
      const candidate = match?.[1];
      if (!candidate) {
        continue;
      }

      if (candidate.startsWith("http://") || candidate.startsWith("https://")) {
        return candidate;
      }

      if (candidate.startsWith("file://")) {
        return candidate;
      }

      return `file://${candidate}`;
    }
  }

  return null;
}

function computeBrowserFactoryBase(rawUrl: string | null): string | null {
  if (!rawUrl) {
    return null;
  }

  const sanitized = rawUrl.split("?")[0]?.split("#")[0] ?? rawUrl;
  const esmMarker = "/dist/esm/naylence/fame/";
  const distMarker = "/dist/";

  if (sanitized.includes(esmMarker)) {
    return sanitized.slice(0, sanitized.indexOf(esmMarker) + esmMarker.length);
  }

  if (rawUrl.includes(BROWSER_DIST_SEGMENT)) {
    return new URL("../esm/naylence/fame/", rawUrl).href;
  }

  if (sanitized.includes(BROWSER_DIST_SEGMENT)) {
    const base = sanitized.slice(
      0,
      sanitized.indexOf(BROWSER_DIST_SEGMENT) + BROWSER_DIST_SEGMENT.length,
    );
    return `${base.replace(/browser\/?$/u, "")}esm/naylence/fame/`;
  }

  if (sanitized.includes(distMarker)) {
    const index = sanitized.indexOf(distMarker);
    const base = sanitized.slice(0, index + distMarker.length);
    return `${base}esm/naylence/fame/`;
  }

  const srcMarker = "/src/naylence/fame/";
  if (sanitized.includes(srcMarker)) {
    const index = sanitized.indexOf(srcMarker);
    const projectRoot = sanitized.slice(0, index);
    return `${projectRoot}/dist/esm/naylence/fame/`;
  }

  if (sanitized.startsWith("http://") || sanitized.startsWith("https://")) {
    try {
      const parsed = new URL(rawUrl);
      const viteDepsSegment = "/node_modules/.vite/deps/";
      if (parsed.pathname.includes(viteDepsSegment)) {
        const baseOrigin = `${parsed.protocol}//${parsed.host}`;
        return `${baseOrigin}/node_modules/@naylence/advanced-security/dist/esm/naylence/fame/`;
      }
    } catch {
      // ignore
    }
  }

  return null;
}

const moduleUrl = detectModuleUrl();
const browserFactoryBase = computeBrowserFactoryBase(moduleUrl);
const prefersSource = typeof moduleUrl === "string" && moduleUrl.includes("/src/");

function resolveFactoryModuleSpecifier(specifier: string): string | null {
  if (specifier.startsWith("../")) {
    return `${FACTORY_MODULE_PREFIX}${specifier.slice("../".length)}`;
  }

  if (specifier.startsWith("./")) {
    return `${FACTORY_MODULE_PREFIX}${specifier.slice("./".length)}`;
  }

  return null;
}

function resolveModuleCandidates(spec: FactoryModuleSpec): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();

  const addCandidate = (candidate: string | null): void => {
    if (!candidate) {
      return;
    }
    if (!seen.has(candidate)) {
      seen.add(candidate);
      candidates.push(candidate);
    }
  };

  if (prefersSource && spec.startsWith("./")) {
    const sourceCandidate = `../${spec.slice(2)}`;
    addCandidate(sourceCandidate);
    if (sourceCandidate.endsWith(".js")) {
      addCandidate(sourceCandidate.replace(/\.js$/u, ".ts"));
    }
  }

  if (browserFactoryBase && spec.startsWith("./")) {
    try {
      const browserCandidate = new URL(
        spec.slice("./".length),
        browserFactoryBase,
      ).href;
      addCandidate(browserCandidate);
      if (browserCandidate.endsWith(".js")) {
        addCandidate(browserCandidate.replace(/\.js$/u, ".ts"));
      }
    } catch {
      // ignore resolution failures for browser base
    }
  }

  const packageCandidate = resolveFactoryModuleSpecifier(spec);
  addCandidate(packageCandidate);
  if (packageCandidate?.endsWith(".js")) {
    addCandidate(packageCandidate.replace(/\.js$/u, ".ts"));
  }

  const fallback = spec.startsWith("./") ? `../${spec.slice(2)}` : spec;
  addCandidate(fallback);
  if (fallback.endsWith(".js")) {
    addCandidate(fallback.replace(/\.js$/u, ".ts"));
  }

  addCandidate(spec);
  if (spec.endsWith(".js")) {
    addCandidate(spec.replace(/\.js$/u, ".ts"));
  }

  return candidates;
}

const registeredModules = new Set<FactoryModuleSpec>();
const inflightModules = new Map<FactoryModuleSpec, Promise<boolean>>();
const browserSkippedModules = new Set<FactoryModuleSpec>();

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.release !== "undefined" &&
    process.release?.name === "node"
  );
}

function shouldSkipModule(spec: FactoryModuleSpec): boolean {
  if (isNodeEnvironment()) {
    return false;
  }

  if (!NODE_ONLY_MODULES.has(spec)) {
    return false;
  }

  if (!browserSkippedModules.has(spec)) {
    console.warn(
      "[advanced-security:factory-manifest] skipped browser-incompatible module",
      spec,
    );
    browserSkippedModules.add(spec);
  }

  return true;
}


function getDynamicImporter(): DynamicImporter | null {
  if (typeof globalThis === "undefined") {
    return null;
  }

  const candidate = (globalThis as {
    __naylenceFactoryDynamicImporter?: unknown;
  }).__naylenceFactoryDynamicImporter;

  if (typeof candidate === "function") {
    return candidate as DynamicImporter;
  }

  return null;
}

async function registerModule(
  spec: FactoryModuleSpec,
  registrar: FactoryRegistrar,
): Promise<boolean> {
  const candidates = resolveModuleCandidates(spec);
  const dynamicImporter = getDynamicImporter();
  const loader = dynamicImporter
    ? (specifier: string) => dynamicImporter(specifier)
    : (specifier: string) => import(/* @vite-ignore */ specifier);

  const attempts: Array<{
    readonly load: () => Promise<unknown>;
    readonly candidate: string;
  }> = [];

  const staticLoader = MODULE_LOADERS?.[spec] as
    | FactoryModuleLoader
    | undefined;
  if (staticLoader) {
    attempts.push({ load: () => staticLoader(), candidate: spec });
  }

  for (const candidate of candidates) {
    attempts.push({ load: () => loader(candidate), candidate });
  }

  const registerFromModule = (mod: unknown): boolean => {
    const meta = (mod as Record<string, unknown>).FACTORY_META as
      | FactoryMetadata
      | undefined;
    const Ctor = (mod as Record<string, unknown>).default as
      | FactoryConstructor
      | undefined;

    if (!meta?.base || !meta?.key || typeof Ctor !== "function") {
      console.warn("[debug] invalid factory module", spec, {
        meta,
        hasCtor: typeof Ctor === "function",
      });
      console.warn(
        "[advanced-security:factory-manifest] skipped",
        spec,
        "— missing FACTORY_META or default export ctor",
      );
      return false;
    }

    const { base, key, ...metadata } = meta;
    const extraMetadata =
      Object.keys(metadata).length > 0 ? metadata : undefined;

    console.log("[debug] registering module", { spec, base, key, metadata: extraMetadata });
    registrar.registerFactory(base, key, Ctor, extraMetadata);
    return true;
  };

  for (const [index, { candidate, load }] of attempts.entries()) {
    try {
      const mod = await load();
      return registerFromModule(mod);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const moduleNotFound =
        message.includes("Cannot find module") ||
        message.includes("ERR_MODULE_NOT_FOUND") ||
        message.includes("Unknown file extension") ||
        message.includes("Failed to fetch dynamically imported module") ||
        message.includes("Failed to resolve module specifier") ||
        message.includes("Importing a module script failed");

      const isLastAttempt = index === attempts.length - 1;
      if (!moduleNotFound || isLastAttempt) {
        console.warn("[debug] failed to import candidate", {
          spec,
          candidate,
          message,
        });
        console.warn(
          "[advanced-security:factory-manifest] skipped",
          spec,
          "-",
          message,
        );
        return false;
      }
    }
  }

  return false;
}

async function registerModuleOnce(
  spec: FactoryModuleSpec,
  registrar: FactoryRegistrar,
): Promise<boolean> {
  if (registeredModules.has(spec)) {
    return false;
  }

  const inflight = inflightModules.get(spec);
  if (inflight) {
    return inflight;
  }

  const registration = (async () => {
    const registered = await registerModule(spec, registrar);
    if (registered) {
      registeredModules.add(spec);
    }
    return registered;
  })();

  inflightModules.set(spec, registration);

  try {
    return await registration;
  } finally {
    inflightModules.delete(spec);
  }
}

async function registerModules(
  modules: readonly FactoryModuleSpec[],
  registrar: FactoryRegistrar,
): Promise<number> {
  if (modules.length === 0) {
    return 0;
  }

  const eligibleModules = modules.filter((spec) => !shouldSkipModule(spec));
  if (eligibleModules.length === 0) {
    return 0;
  }

  const results = await Promise.all(
    eligibleModules.map((spec) => registerModuleOnce(spec, registrar)),
  );
  return results.reduce(
    (count, registered) => (registered ? count + 1 : count),
    0,
  );
}

export interface RegisterAdvancedSecurityFactoriesOptions {
  readonly includeExtras?: boolean;
}

export async function registerAdvancedSecurityFactories(
  registrar: FactoryRegistrar = Registry,
  options?: RegisterAdvancedSecurityFactoriesOptions,
): Promise<void> {
  const newlyRegisteredSecurity = await registerModules(
    SECURITY_MODULES,
    registrar,
  );

  if (newlyRegisteredSecurity > 0) {
    getEncryptionManagerFactoryRegistry().forceRediscovery();
  }

  if (options?.includeExtras === true) {
    await registerModules(EXTRA_MODULES, registrar);
  }
}
