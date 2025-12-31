/**
 * HTTP Policy Authorization Profile
 *
 * Provides the 'policy-http' authorization profile for loading policies over HTTP(S).
 * This profile is similar to 'policy-localfile' from the runtime package but uses
 * the HttpAuthorizationPolicySource instead of LocalFileAuthorizationPolicySource.
 */

import { Expressions } from "@naylence/factory";
import {
  registerProfile,
  AUTHORIZER_FACTORY_BASE_TYPE,
  type TokenVerifierConfig,
} from "@naylence/runtime";

import type { HttpAuthorizationPolicySourceConfig } from "./policy/http-authorization-policy-source-factory.js";

// Environment variable names for HTTP policy source
export const ENV_VAR_AUTH_POLICY_URL = "FAME_AUTH_POLICY_URL";
export const ENV_VAR_AUTH_POLICY_TIMEOUT_MS = "FAME_AUTH_POLICY_TIMEOUT_MS";
export const ENV_VAR_AUTH_POLICY_CACHE_TTL_MS = "FAME_AUTH_POLICY_CACHE_TTL_MS";
export const ENV_VAR_AUTH_POLICY_TOKEN_URL = "FAME_AUTH_POLICY_TOKEN_URL";
export const ENV_VAR_AUTH_POLICY_CLIENT_ID = "FAME_AUTH_POLICY_CLIENT_ID";
export const ENV_VAR_AUTH_POLICY_CLIENT_SECRET = "FAME_AUTH_POLICY_CLIENT_SECRET";
export const ENV_VAR_AUTH_POLICY_AUDIENCE = "FAME_AUTH_POLICY_AUDIENCE";

// Legacy environment variable for backwards compatibility
export const ENV_VAR_AUTH_POLICY_BEARER_TOKEN = "FAME_AUTH_POLICY_BEARER_TOKEN";

// Profile name constant
export const PROFILE_NAME_POLICY_HTTP = "policy-http";

// Re-use JWT verifier env vars from runtime
const ENV_VAR_JWKS_URL = "FAME_JWKS_URL";
const ENV_VAR_JWT_TRUSTED_ISSUER = "FAME_JWT_TRUSTED_ISSUER";

/**
 * Default token verifier configuration using JWKS.
 */
const DEFAULT_VERIFIER_CONFIG: TokenVerifierConfig = {
  type: "JWKSJWTTokenVerifier",
  jwks_url: Expressions.env(ENV_VAR_JWKS_URL),
  issuer: Expressions.env(ENV_VAR_JWT_TRUSTED_ISSUER),
};

/**
 * Creates OAuth2 token provider configuration for HTTP policy source.
 *
 * Uses environment variables for OAuth2 client credentials flow.
 */
function createOAuth2TokenProviderConfig() {
  const tokenUrl = Expressions.env(ENV_VAR_AUTH_POLICY_TOKEN_URL);
  const clientId = Expressions.env(ENV_VAR_AUTH_POLICY_CLIENT_ID);
  const clientSecret = Expressions.env(ENV_VAR_AUTH_POLICY_CLIENT_SECRET);
  const audience = Expressions.env(ENV_VAR_AUTH_POLICY_AUDIENCE);

  return {
    type: "OAuth2ClientCredentialsTokenProvider",
    token_url: tokenUrl,
    tokenUrl,
    client_id: clientId,
    clientId,
    client_secret: clientSecret,
    clientSecret,
    scopes: ["policy.read"],
    audience,
  };
}

/**
 * Default HTTP policy source configuration.
 *
 * Uses environment variables for URL, timeout, and OAuth2 client credentials.
 */
const DEFAULT_HTTP_POLICY_SOURCE: HttpAuthorizationPolicySourceConfig = {
  type: "HttpAuthorizationPolicySource",
  url: Expressions.env(ENV_VAR_AUTH_POLICY_URL) as unknown as string,
  timeout_ms: Expressions.env(
    ENV_VAR_AUTH_POLICY_TIMEOUT_MS,
    "30000",
  ) as unknown as number,
  cache_ttl_ms: Expressions.env(
    ENV_VAR_AUTH_POLICY_CACHE_TTL_MS,
    "300000",
  ) as unknown as number,
  // OAuth2 client credentials token provider
  token_provider: createOAuth2TokenProviderConfig(),
};

/**
 * PolicyAuthorizer configuration using HTTP policy source.
 */
interface PolicyHttpAuthorizerConfig {
  type: "PolicyAuthorizer";
  verifier: TokenVerifierConfig;
  policy_source: HttpAuthorizationPolicySourceConfig;
  [key: string]: unknown;
}

const POLICY_HTTP_PROFILE: PolicyHttpAuthorizerConfig = {
  type: "PolicyAuthorizer",
  verifier: DEFAULT_VERIFIER_CONFIG,
  policy_source: DEFAULT_HTTP_POLICY_SOURCE,
};

// Register the policy-http profile
registerProfile(
  AUTHORIZER_FACTORY_BASE_TYPE,
  PROFILE_NAME_POLICY_HTTP,
  POLICY_HTTP_PROFILE,
  {
    source: "advanced-security:policy-http-authorization-profile",
    allowOverride: true,
  },
);
