/**
 * Global factory registration for all tests.
 * 
 * This ensures that both naylence-runtime and naylence-advanced-security
 * factories are registered before any tests run, preventing race conditions
 * and ensuring all factories are available.
 */
import { registerRuntimeFactories } from "@naylence/runtime";
import { registerAdvancedSecurityFactories } from "../src/naylence/fame/security/register-advanced-security-factories.js";

// Register factories globally before all tests using beforeAll
beforeAll(async () => {
  await registerRuntimeFactories();
  await registerAdvancedSecurityFactories();
});

export {};
