/**
 * Advanced authorization policy module exports.
 *
 * This module provides expression-based authorization policies
 * for the Naylence Advanced Security package.
 *
 * @packageDocumentation
 */

// Expression engine
export * from "./expr/index.js";

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
