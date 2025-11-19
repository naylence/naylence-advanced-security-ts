/**
 * Isomorphic entry point for Naylence Advanced Security.
 *
 * Exposes browser-safe security helpers alongside the factory registrar while
 * installing the shared dynamic importer shim used by Naylence plugins.
 */

export { VERSION } from "./version.js";

export {
  validateJwkX5cCertificate,
  type ValidateJwkX5cCertificateOptions,
  type ValidateJwkX5cCertificateResult,
  publicKeyFromX5c,
  type PublicKeyFromX5cOptions,
} from "./naylence/fame/security/cert/util.js";
export { GRANT_PURPOSE_CA_SIGN } from "./naylence/fame/security/cert/grants.js";
export {
  createEd25519Csr,
  type CreateEd25519CsrOptions,
} from "./naylence/fame/security/cert/browser-csr.js";
export { type CreatedEd25519Csr } from "./naylence/fame/security/cert/csr-types.js";
export {
  CAServiceClient,
  type HttpConnectionGrant,
  type CertificateRequestResponse,
  ENV_VAR_FAME_CA_SERVICE_URL,
  extractCertificateInfo,
  formatCertificateInfo,
} from "./naylence/fame/security/cert/ca-service-client.js";

export * from "./naylence/fame/security/encryption/index.js";

export {
  AdvancedEdDSAEnvelopeSignerFactory,
  FACTORY_META as ADVANCED_EDDSA_ENVELOPE_SIGNER_FACTORY_META,
  type EdDSAEnvelopeSignerConfig,
} from "./naylence/fame/security/signing/eddsa-envelope-signer-factory.js";
export {
  AdvancedEdDSAEnvelopeVerifierFactory,
  FACTORY_META as ADVANCED_EDDSA_ENVELOPE_VERIFIER_FACTORY_META,
  type EdDSAEnvelopeVerifierConfig,
} from "./naylence/fame/security/signing/eddsa-envelope-verifier-factory.js";
export {
  EdDSAEnvelopeVerifier,
  type EdDSAEnvelopeVerifierOptions,
  type SigningConfigInstance,
} from "./naylence/fame/security/signing/eddsa-envelope-verifier.js";

export * from "./naylence/fame/security/keys/index.js";

export * from "./naylence/fame/stickiness/index.js";
export * from "./naylence/fame/welcome/index.js";

export {
  registerAdvancedSecurityFactories,
  type RegisterAdvancedSecurityFactoriesOptions,
} from "./naylence/fame/security/register-advanced-security-factories.js";

type PluginModule = Record<string, unknown>;
type PluginModuleLoader = (specifier: string) => Promise<PluginModule>;

const pluginModulePromise = import("./plugin.js") as Promise<PluginModule>;

const globalScope = globalThis as Record<string, unknown>;
const FACTORY_MODULE_PREFIX = "@naylence/advanced-security/naylence/fame/";
const RUNTIME_LOADER_KEY = "__naylenceFactoryDynamicImporter";
const ADVANCED_SECURITY_LOADER_MARK = Symbol.for(
  "__naylenceAdvancedSecurityLoader__",
);

const isAdvancedSecurityPluginSpecifier = (specifier: string): boolean =>
  specifier === "@naylence/advanced-security" ||
  specifier === "@naylence/advanced-security/" ||
  specifier === "@naylence/advanced-security/plugin" ||
  specifier === "@naylence/advanced-security/plugin.js" ||
  specifier === "@naylence/advanced-security/dist/esm/plugin.js";

const resolveFactoryModuleSpecifier = (specifier: string): string | null => {
  if (specifier.startsWith("../")) {
    const relativePath = specifier.slice("../".length);
    return `${FACTORY_MODULE_PREFIX}${relativePath}`;
  }

  if (specifier.startsWith("./")) {
    const relativePath = specifier.slice("./".length);
    return `${FACTORY_MODULE_PREFIX}${relativePath}`;
  }

  return null;
};

const isModuleNotFoundError = (error: unknown): boolean => {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("Cannot find module") ||
    message.includes("ERR_MODULE_NOT_FOUND") ||
    message.includes("Unknown file extension") ||
    message.includes("Failed to fetch dynamically imported module") ||
    message.includes("Failed to resolve module specifier") ||
    message.includes("Importing a module script failed")
  );
};

const ensureAdvancedSecurityPluginLoader = (): PluginModuleLoader => {
  const existing = Reflect.get(
    globalScope,
    RUNTIME_LOADER_KEY,
  ) as PluginModuleLoader | undefined;

  if (
    typeof existing === "function" &&
    Reflect.get(existing, ADVANCED_SECURITY_LOADER_MARK)
  ) {
    return existing;
  }

  const fallbackLoader =
    typeof existing === "function" ? existing : undefined;

  const loader: PluginModuleLoader = async (
    specifier: string,
  ): Promise<PluginModule> => {
    if (isAdvancedSecurityPluginSpecifier(specifier)) {
      return pluginModulePromise;
    }

    const remapped = resolveFactoryModuleSpecifier(specifier);
    if (remapped) {
      try {
        return await import(/* @vite-ignore */ remapped);
      } catch (error) {
        if (!fallbackLoader || !isModuleNotFoundError(error)) {
          throw error;
        }
      }
    }

    if (fallbackLoader) {
      return fallbackLoader(specifier);
    }

    return import(/* @vite-ignore */ specifier);
  };

  Reflect.set(loader, ADVANCED_SECURITY_LOADER_MARK, true);
  Reflect.set(globalScope, RUNTIME_LOADER_KEY, loader);

  return loader;
};

export const __advancedSecurityPluginLoader =
  ensureAdvancedSecurityPluginLoader();

