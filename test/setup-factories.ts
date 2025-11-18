/**
 * Global factory registration for all tests.
 * 
 * This ensures that both naylence-runtime and naylence-advanced-security
 * factories are registered before any tests run, preventing race conditions
 * and ensuring all factories are available.
 */
import { registerRuntimeFactories } from "@naylence/runtime";
import { registerAdvancedSecurityFactories } from "../src/naylence/fame/security/register-advanced-security-factories.js";

type TestLifecycle = (callback: () => unknown | Promise<unknown>) => unknown;

const lifecycleHook = (globalThis as { beforeAll?: TestLifecycle }).beforeAll;

if (typeof lifecycleHook !== "function") {
	throw new Error("Test environment is missing a beforeAll hook");
}

// Register factories globally before all tests using the detected hook
lifecycleHook(async () => {
  await registerRuntimeFactories();
  await registerAdvancedSecurityFactories();
});

export {};
