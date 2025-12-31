/**
 * Advanced authorization policy module exports.
 *
 * This module provides expression-based authorization policies
 * for the Naylence Advanced Security package.
 *
 * @packageDocumentation
 */

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

// HTTP policy source
export {
  HttpAuthorizationPolicySource,
  type HttpAuthorizationPolicySourceOptions,
  type HttpPolicySourceMetadata,
  type HttpMethod,
} from "./http-authorization-policy-source.js";

// HTTP policy source factory
export {
  HttpAuthorizationPolicySourceFactory,
  FACTORY_META as HTTP_AUTHORIZATION_POLICY_SOURCE_FACTORY_META,
  type HttpAuthorizationPolicySourceConfig,
} from "./http-authorization-policy-source-factory.js";
