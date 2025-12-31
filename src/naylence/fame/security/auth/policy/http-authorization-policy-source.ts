/**
 * HTTP-based authorization policy source.
 *
 * Loads authorization policies from an HTTP endpoint supporting JSON or YAML.
 * Supports bearer authentication via TokenProvider and HTTP caching via ETag.
 *
 * This is a Node.js-only implementation.
 *
 * @packageDocumentation
 */

import { parse as parseYaml } from "yaml";

import type {
  AuthorizationPolicy,
  AuthorizationPolicySource,
  AuthorizationPolicyConfig,
  TokenProvider,
} from "@naylence/runtime";
import {
  AuthorizationPolicyFactory,
  getLogger,
} from "@naylence/runtime";

const logger = getLogger(
  "naylence.fame.security.auth.policy.http_authorization_policy_source",
);

/**
 * HTTP method for the policy request.
 */
export type HttpMethod = "GET" | "POST" | "PUT";

/**
 * Metadata about the last fetch operation.
 *
 * Useful for verification, debugging, and monitoring.
 */
export interface HttpPolicySourceMetadata {
  /**
   * The URL from which the policy was fetched.
   */
  url: string;

  /**
   * HTTP status code of the last successful fetch.
   */
  status: number;

  /**
   * ETag from the last successful response.
   */
  etag?: string;

  /**
   * Timestamp when the policy was last fetched.
   */
  fetchedAt: number;

  /**
   * Cache-Control max-age value in seconds, if present.
   */
  maxAgeSeconds?: number;

  /**
   * Computed expiration time based on max-age.
   */
  expiresAt?: number;
}

/**
 * Configuration options for HttpAuthorizationPolicySource.
 */
export interface HttpAuthorizationPolicySourceOptions {
  /**
   * The URL to fetch the policy from.
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
  timeoutMs?: number;

  /**
   * Additional headers to include in the request.
   */
  headers?: Record<string, string>;

  /**
   * Token provider for bearer authentication.
   */
  tokenProvider?: TokenProvider;

  /**
   * Prefix for the Authorization header.
   * @default "Bearer "
   */
  bearerPrefix?: string;

  /**
   * Configuration for the policy factory to use when parsing the loaded data.
   * Determines which AuthorizationPolicy implementation is created.
   *
   * If not specified, the policy definition from the response is used directly
   * as the factory configuration (must include a 'type' field).
   */
  policyFactory?: AuthorizationPolicyConfig | Record<string, unknown>;

  /**
   * Fallback cache TTL in milliseconds when server provides no caching headers.
   * @default 300000 (5 minutes)
   */
  cacheTtlMs?: number;
}

/**
 * Cached policy state.
 */
interface CachedPolicyState {
  policy: AuthorizationPolicy;
  metadata: HttpPolicySourceMetadata;
  rawDefinition: Record<string, unknown>;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseJson(content: string): Record<string, unknown> {
  const parsed = JSON.parse(content);
  if (!isPlainObject(parsed)) {
    throw new Error("Parsed JSON policy must be an object");
  }
  return parsed;
}

function parseYamlContent(content: string): Record<string, unknown> {
  const parsed = parseYaml(content ?? "") as unknown;
  if (parsed == null) {
    return {};
  }
  if (!isPlainObject(parsed)) {
    throw new Error("Parsed YAML policy must be an object");
  }
  return parsed;
}

/**
 * Detect whether content is JSON or YAML based on Content-Type header.
 * Falls back to sniffing the content if Content-Type is not definitive.
 */
function detectFormat(
  contentType: string | null,
  content: string,
): "json" | "yaml" {
  if (contentType) {
    const lower = contentType.toLowerCase();
    if (
      lower.includes("application/json") ||
      lower.includes("text/json")
    ) {
      return "json";
    }
    if (
      lower.includes("application/yaml") ||
      lower.includes("application/x-yaml") ||
      lower.includes("text/yaml") ||
      lower.includes("text/x-yaml")
    ) {
      return "yaml";
    }
  }

  // Sniff by first non-whitespace character
  const trimmed = content.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return "json";
  }

  // Default to YAML
  return "yaml";
}

/**
 * Parse Cache-Control header to extract max-age value.
 */
function parseMaxAge(cacheControl: string | null): number | undefined {
  if (!cacheControl) {
    return undefined;
  }

  const match = cacheControl.match(/max-age\s*=\s*(\d+)/i);
  if (match && match[1]) {
    const seconds = parseInt(match[1], 10);
    if (Number.isFinite(seconds) && seconds >= 0) {
      return seconds;
    }
  }

  return undefined;
}

/**
 * An authorization policy source that loads policy definitions from an HTTP endpoint.
 *
 * Supports JSON and YAML formats, bearer authentication via TokenProvider,
 * and HTTP caching via ETag and Cache-Control headers.
 *
 * This is a Node.js-only implementation that uses fetch.
 */
export class HttpAuthorizationPolicySource implements AuthorizationPolicySource {
  private readonly url: string;
  private readonly method: HttpMethod;
  private readonly timeoutMs: number;
  private readonly headers: Record<string, string>;
  private readonly tokenProvider: TokenProvider | undefined;
  private readonly bearerPrefix: string;
  private readonly policyFactoryConfig:
    | AuthorizationPolicyConfig
    | Record<string, unknown>
    | undefined;
  private readonly cacheTtlMs: number;

  private cachedState: CachedPolicyState | null = null;
  private inflightFetch: Promise<AuthorizationPolicy> | null = null;

  constructor(options: HttpAuthorizationPolicySourceOptions) {
    if (!options.url || typeof options.url !== "string") {
      throw new Error(
        "HttpAuthorizationPolicySource requires a valid URL",
      );
    }

    this.url = options.url;
    this.method = options.method ?? "GET";
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.headers = { ...options.headers };
    this.tokenProvider = options.tokenProvider;
    this.bearerPrefix = options.bearerPrefix ?? "Bearer ";
    this.policyFactoryConfig = options.policyFactory;
    this.cacheTtlMs = options.cacheTtlMs ?? 300000; // 5 minutes default
  }

  /**
   * Loads the authorization policy from the configured HTTP endpoint.
   *
   * Returns a cached policy if still fresh (based on TTL or cache headers).
   * Multiple concurrent calls are de-duplicated (single-flight pattern).
   *
   * @returns The loaded authorization policy
   */
  async loadPolicy(): Promise<AuthorizationPolicy> {
    // Return cached policy if still fresh
    if (this.cachedState && this.isCacheFresh()) {
      logger.debug("returning_cached_policy", {
        url: this.url,
        fetchedAt: this.cachedState.metadata.fetchedAt,
        expiresAt: this.cachedState.metadata.expiresAt,
      });
      return this.cachedState.policy;
    }

    // De-duplicate concurrent requests
    if (this.inflightFetch) {
      return this.inflightFetch;
    }

    this.inflightFetch = this.fetchPolicy(false);

    try {
      return await this.inflightFetch;
    } finally {
      this.inflightFetch = null;
    }
  }

  /**
   * Forces a reload of the policy from the HTTP endpoint.
   *
   * Bypasses cache freshness checks and always fetches from the server.
   * If the fetch fails, the existing cached policy is preserved and the error is thrown.
   *
   * @returns The reloaded authorization policy
   */
  async reloadPolicy(): Promise<AuthorizationPolicy> {
    // Clear inflight to force a new request
    this.inflightFetch = null;

    return this.fetchPolicy(true);
  }

  /**
   * Clears the cached policy, forcing a fresh fetch on the next loadPolicy() call.
   */
  clearCache(): void {
    this.cachedState = null;
    this.inflightFetch = null;
  }

  /**
   * Returns metadata about the last successful fetch.
   *
   * Useful for verification, monitoring, or debugging.
   */
  getMetadata(): HttpPolicySourceMetadata | undefined {
    return this.cachedState?.metadata;
  }

  /**
   * Returns the raw policy definition from the last successful fetch.
   *
   * Useful for verification or reprocessing.
   */
  getRawDefinition(): Record<string, unknown> | undefined {
    return this.cachedState?.rawDefinition;
  }

  private isCacheFresh(): boolean {
    if (!this.cachedState) {
      return false;
    }

    const now = Date.now();
    const { expiresAt } = this.cachedState.metadata;

    if (expiresAt !== undefined) {
      return now < expiresAt;
    }

    // No expiration info, check against default TTL
    const fetchedAt = this.cachedState.metadata.fetchedAt;
    return now < fetchedAt + this.cacheTtlMs;
  }

  private async fetchPolicy(forceRefresh: boolean): Promise<AuthorizationPolicy> {
    logger.debug("fetching_policy", {
      url: this.url,
      method: this.method,
      forceRefresh,
    });

    const requestHeaders: Record<string, string> = {
      Accept: "application/json, application/yaml, text/yaml, */*",
      ...this.headers,
    };

    // Add bearer token if token provider is configured
    if (this.tokenProvider) {
      try {
        const token = await this.tokenProvider.getToken();
        if (token && token.value) {
          requestHeaders["Authorization"] = `${this.bearerPrefix}${token.value}`;
          logger.debug("added_bearer_token", { url: this.url });
        }
      } catch (error) {
        logger.warning("token_provider_failed", {
          url: this.url,
          error: error instanceof Error ? error.message : String(error),
        });
        // Continue without token - let the server decide if auth is required
      }
    }

    // Add If-None-Match header for conditional request if we have a cached ETag
    // and this is not a forced refresh
    if (!forceRefresh && this.cachedState?.metadata.etag) {
      requestHeaders["If-None-Match"] = this.cachedState.metadata.etag;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(this.url, {
        method: this.method,
        headers: requestHeaders,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle 304 Not Modified - return cached policy
      if (response.status === 304 && this.cachedState) {
        logger.debug("policy_not_modified", {
          url: this.url,
          etag: this.cachedState.metadata.etag,
        });

        // Update freshness timestamps
        const now = Date.now();
        const cacheControl = response.headers.get("Cache-Control");
        const maxAgeSeconds = parseMaxAge(cacheControl);
        const expiresAt = maxAgeSeconds !== undefined
          ? now + maxAgeSeconds * 1000
          : now + this.cacheTtlMs;

        this.cachedState = {
          ...this.cachedState,
          metadata: {
            ...this.cachedState.metadata,
            fetchedAt: now,
            maxAgeSeconds,
            expiresAt,
          },
        };

        return this.cachedState.policy;
      }

      if (!response.ok) {
        const errorMessage = `HTTP ${response.status}: ${response.statusText}`;
        logger.error("policy_fetch_failed", {
          url: this.url,
          status: response.status,
          statusText: response.statusText,
        });

        // If we have a cached policy, preserve it and throw
        if (this.cachedState) {
          throw new Error(
            `Failed to fetch policy from ${this.url}: ${errorMessage}. ` +
            "Using last known good policy.",
          );
        }

        throw new Error(`Failed to fetch policy from ${this.url}: ${errorMessage}`);
      }

      // Parse the response
      const contentType = response.headers.get("Content-Type");
      const content = await response.text();
      const format = detectFormat(contentType, content);

      let policyDefinition: Record<string, unknown>;
      try {
        if (format === "json") {
          policyDefinition = parseJson(content);
        } else {
          policyDefinition = parseYamlContent(content);
        }
      } catch (parseError) {
        const message = parseError instanceof Error
          ? parseError.message
          : String(parseError);
        logger.error("policy_parse_failed", {
          url: this.url,
          format,
          error: message,
        });

        // Preserve cached policy on parse failure
        if (this.cachedState) {
          throw new Error(
            `Failed to parse policy from ${this.url}: ${message}. ` +
            "Using last known good policy.",
          );
        }

        throw new Error(`Failed to parse policy from ${this.url}: ${message}`);
      }

      logger.debug("parsed_policy_definition", {
        url: this.url,
        format,
        hasType: "type" in policyDefinition,
      });

      // Build the policy using the factory
      const policy = await this.buildPolicy(policyDefinition);

      // Update cache
      const now = Date.now();
      const etag = response.headers.get("ETag") ?? undefined;
      const cacheControl = response.headers.get("Cache-Control");
      const maxAgeSeconds = parseMaxAge(cacheControl);
      const expiresAt = maxAgeSeconds !== undefined
        ? now + maxAgeSeconds * 1000
        : now + this.cacheTtlMs;

      this.cachedState = {
        policy,
        rawDefinition: policyDefinition,
        metadata: {
          url: this.url,
          status: response.status,
          etag,
          fetchedAt: now,
          maxAgeSeconds,
          expiresAt,
        },
      };

      logger.info("loaded_policy_from_http", {
        url: this.url,
        status: response.status,
        format,
        etag,
        maxAgeSeconds,
      });

      return policy;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof Error && error.name === "AbortError") {
        const timeoutError = new Error(
          `Request to ${this.url} timed out after ${this.timeoutMs}ms`,
        );

        logger.error("policy_fetch_timeout", {
          url: this.url,
          timeoutMs: this.timeoutMs,
        });

        // Preserve cached policy on timeout
        if (this.cachedState) {
          throw timeoutError;
        }

        throw timeoutError;
      }

      throw error;
    }
  }

  private async buildPolicy(
    policyDefinition: Record<string, unknown>,
  ): Promise<AuthorizationPolicy> {
    // Determine the factory configuration to use
    const factoryConfig = this.policyFactoryConfig ?? policyDefinition;

    // Ensure we have a type field for the factory
    if (!("type" in factoryConfig) || typeof factoryConfig.type !== "string") {
      logger.warning("policy_type_missing_defaulting_to_basic", {
        url: this.url,
      });
      (factoryConfig as Record<string, unknown>).type = "BasicAuthorizationPolicy";
    }

    // Build the factory config with the policy definition
    // The response content IS the policy definition, so we extract the type
    // and wrap the remaining content as the policyDefinition
    const { type: definitionType, ...restOfDefinition } = policyDefinition as
      { type?: string } & Record<string, unknown>;
    const resolvedType =
      typeof definitionType === "string" && definitionType.trim().length > 0
        ? definitionType
        : (factoryConfig as Record<string, unknown>).type;
    const mergedConfig =
      this.policyFactoryConfig != null
        ? { ...this.policyFactoryConfig, policyDefinition }
        : { type: resolvedType, policyDefinition: restOfDefinition };

    const policy = await AuthorizationPolicyFactory.createAuthorizationPolicy(
      mergedConfig,
    );

    if (!policy) {
      throw new Error(
        `Failed to create authorization policy from ${this.url}`,
      );
    }

    return policy;
  }
}
