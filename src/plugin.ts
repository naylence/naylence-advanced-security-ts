/**
 * Naylence Advanced Security plugin entry point for the naylence-factory plugin ecosystem.
 */
import type { FamePlugin } from "naylence-factory";
import { Registry } from "naylence-factory";

import { registerAdvancedSecurityFactories } from "./naylence/fame/security/register-advanced-security-factories.js";

type FactoryRegistrar = Pick<typeof Registry, "registerFactory">;

export async function registerAdvancedSecurityPluginFactories(
  registrar: FactoryRegistrar = Registry
): Promise<void> {
  await registerAdvancedSecurityFactories(registrar, { includeExtras: true });
}

let initialized = false;
let initializing: Promise<void> | null = null;

const advancedSecurityPlugin: FamePlugin = {
  name: "naylence:advanced-security",
  async register(): Promise<void> {
    if (initialized) {
      return;
    }

    if (initializing) {
      await initializing;
      return;
    }

    initializing = (async () => {
      try {
        await registerAdvancedSecurityPluginFactories();
        initialized = true;
      } finally {
        initializing = null;
      }
    })();

    await initializing;
  },
};

export default advancedSecurityPlugin;

export const ADVANCED_SECURITY_PLUGIN_SPECIFIER = advancedSecurityPlugin.name;
