import type { ResourceFactory } from "@naylence/factory";
import { Registry } from "@naylence/factory";

import { MODULES, type FactoryModuleSpec } from "../factory-manifest.js";
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

const SECURITY_PREFIX = "./security/" as const;
const SECURITY_MODULES = MODULES.filter((spec) =>
  spec.startsWith(SECURITY_PREFIX),
);
const EXTRA_MODULES = MODULES.filter(
  (spec) => !spec.startsWith(SECURITY_PREFIX),
);

const registeredModules = new Set<FactoryModuleSpec>();
const inflightModules = new Map<FactoryModuleSpec, Promise<boolean>>();

function resolveModuleCandidates(spec: FactoryModuleSpec): string[] {
  const base = spec.startsWith("./") ? `../${spec.slice(2)}` : spec;

  if (base.endsWith(".js")) {
    return [base.replace(/\.js$/u, ".ts"), base];
  }

  return [base];
}

async function registerModule(
  spec: FactoryModuleSpec,
  registrar: FactoryRegistrar,
): Promise<boolean> {
  const candidates = resolveModuleCandidates(spec);

  for (const candidate of candidates) {
    try {
      const mod = await import(candidate);
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

      //console.log("[debug] registering module", { spec, base, key, metadata: extraMetadata });
      registrar.registerFactory(base, key, Ctor, extraMetadata);
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const moduleNotFound =
        message.includes("Cannot find module") ||
        message.includes("ERR_MODULE_NOT_FOUND") ||
        message.includes("Unknown file extension");

      const isLastCandidate = candidate === candidates[candidates.length - 1];
      if (!moduleNotFound || isLastCandidate) {
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

  const results = await Promise.all(
    modules.map((spec) => registerModuleOnce(spec, registrar)),
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
