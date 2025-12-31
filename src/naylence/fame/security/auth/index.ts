/**
 * Advanced security authentication/authorization module exports.
 *
 * @packageDocumentation
 */

export * from "./policy/index.js";

// Authorization profiles
export {
  PROFILE_NAME_POLICY_HTTP,
  ENV_VAR_AUTH_POLICY_URL,
  ENV_VAR_AUTH_POLICY_TIMEOUT_MS,
  ENV_VAR_AUTH_POLICY_CACHE_TTL_MS,
  ENV_VAR_AUTH_POLICY_BEARER_TOKEN,
} from "./policy-http-authorization-profile.js";
