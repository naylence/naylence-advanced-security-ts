/**
 * Advanced authorization policy module exports.
 *
 * This module provides expression-based authorization policies
 * for the Naylence Advanced Security package.
 *
 * @packageDocumentation
 */

// Auth expression helpers
export {
  createAuthFunctionRegistry,
  createSecurityBindings,
  normalizeEncryptionLevelFromAlg,
  type AuthFunctionRegistryOptions,
  type EncryptionLevel,
  type SecurityBindings,
} from "./expr-builtins.js";

// Expression authorization policy
export {
  AdvancedAuthorizationPolicy,
  type AdvancedAuthorizationPolicyOptions,
} from "./advanced-authorization-policy.js";

// Factory
export {
  AdvancedAuthorizationPolicyFactory,
  FACTORY_META as ADVANCED_AUTHORIZATION_POLICY_FACTORY_META,
  type AdvancedAuthorizationPolicyConfig,
} from "./advanced-authorization-policy-factory.js";
