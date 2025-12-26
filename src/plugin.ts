/**
 * Naylence Advanced Security plugin entry point for the naylence-factory plugin ecosystem.
 */
import type { FamePlugin } from "@naylence/factory";
import { Registry } from "@naylence/factory";

import { registerAdvancedSecurityFactories } from "./naylence/fame/security/register-advanced-security-factories.js";
import { VERSION } from './version.js';

type FactoryRegistrar = Pick<typeof Registry, "registerFactory">;

export async function registerAdvancedSecurityPluginFactories(
  registrar: FactoryRegistrar = Registry,
): Promise<void> {
  await registerAdvancedSecurityFactories(registrar, { includeExtras: true });
}

let initialized = false;
let initializing: Promise<void> | null = null;

const advancedSecurityPlugin: FamePlugin = {
  name: "naylence:advanced-security",
  version: VERSION,
  async register(): Promise<void> {
    // console.log('[naylence:advanced-security] register() called, initialized=', initialized);
    if (initialized) {
      // console.log('[naylence:advanced-security] already initialized, skipping');
      return;
    }

    if (initializing) {
      console.log(
        "[naylence:advanced-security] already initializing, awaiting...",
      );
      await initializing;
      return;
    }

    initializing = (async () => {
      try {
        // console.log('[naylence:advanced-security] registering advanced security factories...');
        await registerAdvancedSecurityPluginFactories();
        
        // Import modules with side-effect registrations (not in manifest)
        await import('./naylence/fame/security/strict-overlay-security-profile.js');
        
        // console.log('[naylence:advanced-security] advanced security factories registered');
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
