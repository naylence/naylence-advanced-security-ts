/**
 * Factory for creating HttpAuthorizationPolicySource instances.
 *
 * @packageDocumentation
 */

import type { AuthorizationPolicySource, TokenProvider } from "@naylence/runtime";
import {
  AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
  AuthorizationPolicySourceFactory,
  type AuthorizationPolicySourceConfig,
  type AuthorizationPolicyConfig,
  TokenProviderFactory,
  type TokenProviderConfig,
} from "@naylence/runtime";

import type {
  HttpAuthorizationPolicySourceOptions,
  HttpMethod,
} from "./http-authorization-policy-source.js";

/**
 * Configuration for HttpAuthorizationPolicySource.
 *
 * Supports both camelCase and snake_case property names for flexibility.
 */
export interface HttpAuthorizationPolicySourceConfig
  extends AuthorizationPolicySourceConfig {
  type: "HttpAuthorizationPolicySource";

  /**
   * The URL to fetch the policy from (required).
   */
  url: string;

  /**
   * HTTP method to use.
   * @default "GET"
   */
  method?: HttpMethod;

  /**
   * Request timeout in milliseconds.
   * @default 30000
   */
  timeout_ms?: number;

  /**
   * Additional headers to include in the request.
   */
  headers?: Record<string, string>;

  /**
   * Token provider configuration for bearer authentication.
   */
  token_provider?: TokenProviderConfig | Record<string, unknown>;

  /**
   * Prefix for the Authorization header.
   * @default "Bearer "
   */
  bearer_prefix?: string;

  /**
   * Configuration for the policy factory to use when parsing the loaded data.
   */
  policy_factory?: AuthorizationPolicyConfig | Record<string, unknown>;

  /**
   * Polling interval in milliseconds (reserved for future use).
   */
  poll_interval_ms?: number;

  /**
   * Fallback cache TTL in milliseconds when server provides no caching headers.
   * @default 300000 (5 minutes)
   */
  cache_ttl_ms?: number;
}

type HttpModuleType = typeof import("./http-authorization-policy-source.js");

let httpModulePromise: Promise<HttpModuleType> | null = null;

async function getHttpModule(): Promise<HttpModuleType> {
  if (!httpModulePromise) {
    httpModulePromise = import("./http-authorization-policy-source.js");
  }
  return httpModulePromise;
}

interface NormalizedConfig {
  url: string;
  method: HttpMethod;
  timeoutMs: number;
  headers?: Record<string, string>;
  tokenProviderConfig?: TokenProviderConfig | Record<string, unknown>;
  bearerPrefix: string;
  policyFactory?: AuthorizationPolicyConfig | Record<string, unknown>;
  cacheTtlMs: number;
}

function normalizeConfig(
  config?: HttpAuthorizationPolicySourceConfig | Record<string, unknown> | null,
): NormalizedConfig {
  if (!config) {
    throw new Error(
      "HttpAuthorizationPolicySourceFactory requires a configuration with a url",
    );
  }

  const candidate = config as Record<string, unknown>;

  const url = candidate.url;
  if (typeof url !== "string" || url.trim().length === 0) {
    throw new Error(
      "HttpAuthorizationPolicySourceConfig requires a non-empty url",
    );
  }

  // Support both camelCase and snake_case
  const method = (candidate.method as HttpMethod | undefined) ?? "GET";
  if (!["GET", "POST", "PUT"].includes(method)) {
    throw new Error(
      `Invalid method "${String(method)}". Must be "GET", "POST", or "PUT"`,
    );
  }

  const timeoutMs =
    (candidate.timeout_ms as number | undefined) ??
    (candidate.timeoutMs as number | undefined) ??
    30000;
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("timeout_ms must be a positive number");
  }

  const headers = candidate.headers as Record<string, string> | undefined;
  if (headers !== undefined && typeof headers !== "object") {
    throw new Error("headers must be an object");
  }

  const tokenProviderConfig =
    (candidate.token_provider as TokenProviderConfig | undefined) ??
    (candidate.tokenProvider as TokenProviderConfig | undefined);

  const bearerPrefix =
    (candidate.bearer_prefix as string | undefined) ??
    (candidate.bearerPrefix as string | undefined) ??
    "Bearer ";

  const policyFactory =
    (candidate.policy_factory as AuthorizationPolicyConfig | undefined) ??
    (candidate.policyFactory as AuthorizationPolicyConfig | undefined);

  const cacheTtlMs =
    (candidate.cache_ttl_ms as number | undefined) ??
    (candidate.cacheTtlMs as number | undefined) ??
    300000;
  if (typeof cacheTtlMs !== "number" || !Number.isFinite(cacheTtlMs) || cacheTtlMs < 0) {
    throw new Error("cache_ttl_ms must be a non-negative number");
  }

  return {
    url: url.trim(),
    method,
    timeoutMs,
    headers,
    tokenProviderConfig,
    bearerPrefix,
    policyFactory,
    cacheTtlMs,
  };
}

/**
 * Factory metadata for registration.
 */
export const FACTORY_META = {
  base: AUTHORIZATION_POLICY_SOURCE_FACTORY_BASE_TYPE,
  key: "HttpAuthorizationPolicySource",
} as const;

/**
 * Factory for creating HttpAuthorizationPolicySource instances.
 *
 * This factory uses lazy loading to avoid pulling in Node.js-specific
 * code (fetch operations) in browser environments where it may not work.
 */
export class HttpAuthorizationPolicySourceFactory extends AuthorizationPolicySourceFactory<HttpAuthorizationPolicySourceConfig> {
  public readonly type = "HttpAuthorizationPolicySource";

  /**
   * Creates an HttpAuthorizationPolicySource from the given configuration.
   *
   * @param config - Configuration specifying the policy URL and options
   * @returns The created policy source
   */
  public async create(
    config?:
      | HttpAuthorizationPolicySourceConfig
      | Record<string, unknown>
      | null,
  ): Promise<AuthorizationPolicySource> {
    const normalized = normalizeConfig(config);

    // Create token provider if configured
    let tokenProvider: TokenProvider | undefined;
    if (normalized.tokenProviderConfig) {
      tokenProvider = await TokenProviderFactory.createTokenProvider(
        normalized.tokenProviderConfig,
      );
    }

    const { HttpAuthorizationPolicySource } = await getHttpModule();

    const options: HttpAuthorizationPolicySourceOptions = {
      url: normalized.url,
      method: normalized.method,
      timeoutMs: normalized.timeoutMs,
      headers: normalized.headers,
      tokenProvider,
      bearerPrefix: normalized.bearerPrefix,
      policyFactory: normalized.policyFactory,
      cacheTtlMs: normalized.cacheTtlMs,
    };

    return new HttpAuthorizationPolicySource(options);
  }
}

export default HttpAuthorizationPolicySourceFactory;
