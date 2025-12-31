/**
 * Auth Policy Server - Authorization Policy HTTP endpoint
 *
 * Provides authorization policies via HTTP using Fastify.
 * Supports OAuth2 JWT authentication and ETag-based caching.
 * Serves multiple policies by ID from a configurable directory.
 * This is a development server for testing HTTP policy source functionality.
 *
 * Policy files should be named: policy-{policy_id}.yaml or policy-{policy_id}.json
 * Example: policy-production.yaml, policy-dev.json
 *
 * Authentication:
 * - Set FAME_OAUTH2_ISSUER to enable OAuth2 JWT validation
 * - Optionally set FAME_OAUTH2_AUDIENCE, FAME_OAUTH2_JWKS_URL
 * - If no OAuth2 config provided, authentication is disabled (dev mode)
 */

import { createHash } from "node:crypto";
import Fastify from "fastify";
import {
  realpathSync,
  readFileSync,
  existsSync,
  statSync,
  readdirSync,
  watch,
} from "node:fs";
import { resolve, extname, join } from "node:path";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";

// Simple console logger for policy server
const logger = {
  info: (event: string, meta?: Record<string, unknown>) => {
    console.log(`[INFO] ${event}`, meta || "");
  },
  warning: (event: string, meta?: Record<string, unknown>) => {
    console.warn(`[WARNING] ${event}`, meta || "");
  },
  error: (event: string, meta?: Record<string, unknown>) => {
    console.error(`[ERROR] ${event}`, meta || "");
  },
  debug: (event: string, meta?: Record<string, unknown>) => {
    const logLevel = (process.env.FAME_LOG_LEVEL || "info").toLowerCase();
    if (logLevel === "debug" || logLevel === "trace") {
      console.log(`[DEBUG] ${event}`, meta || "");
    }
  },
};

// Environment variables
const ENV_VAR_FAME_APP_HOST = "FAME_APP_HOST";
const ENV_VAR_FAME_APP_PORT = "FAME_APP_PORT";
const ENV_VAR_FAME_POLICY_DIR = "FAME_POLICY_DIR";
// OAuth2 configuration
const ENV_VAR_OAUTH2_ISSUER = "FAME_OAUTH2_ISSUER";
const ENV_VAR_OAUTH2_AUDIENCE = "FAME_OAUTH2_AUDIENCE";
const ENV_VAR_OAUTH2_JWKS_URL = "FAME_OAUTH2_JWKS_URL";
const ENV_VAR_OAUTH2_REQUIRED_SCOPES = "FAME_OAUTH2_REQUIRED_SCOPES";

// Policy file naming pattern: policy-{id}.yaml or policy-{id}.json
const POLICY_FILE_PATTERN = /^policy-(.+)\.(ya?ml|json)$/i;

/**
 * Default authorization policy for development.
 * Allows all operations - suitable for testing only.
 */
const DEFAULT_POLICY = {
  version: "1",
  type: "AdvancedAuthorizationPolicy",
  default_effect: "deny",
  rules: [
    {
      id: "allow-all-dev",
      effect: "allow",
      comment: "Development policy - allows all operations",
    },
  ],
};

interface PolicyEntry {
  id: string;
  policy: Record<string, unknown>;
  policyContent: string;
  etag: string;
  lastModified: Date;
  filePath: string;
  format: "yaml" | "json";
}

interface PolicyServerState {
  policyDir?: string;
  policies: Map<string, PolicyEntry>;
}

/**
 * Compute ETag from content using SHA-256.
 */
function computeEtag(content: string): string {
  const hash = createHash("sha256");
  hash.update(content, "utf-8");
  return `"${hash.digest("hex").substring(0, 16)}"`;
}

/**
 * Extract policy ID from filename.
 * Expected format: policy-{id}.yaml or policy-{id}.json
 */
function extractPolicyId(filename: string): { id: string; format: "yaml" | "json" } | null {
  const match = POLICY_FILE_PATTERN.exec(filename);
  if (!match) {
    return null;
  }
  const id = match[1]!;
  const ext = match[2]?.toLowerCase();
  const format = ext === "json" ? "json" : "yaml";
  return { id, format };
}

/**
 * Load a single policy from file.
 */
function loadPolicyFile(filePath: string): Omit<PolicyEntry, "id"> | null {
  try {
    const content = readFileSync(filePath, "utf-8");
    const ext = extname(filePath).toLowerCase();

    let policy: Record<string, unknown>;
    if (ext === ".json") {
      policy = JSON.parse(content) as Record<string, unknown>;
    } else {
      policy = parseYaml(content) as Record<string, unknown>;
    }

    const stats = statSync(filePath);
    const format = ext === ".json" ? "json" : "yaml";

    return {
      policy,
      policyContent: content,
      etag: computeEtag(content),
      lastModified: stats.mtime,
      filePath,
      format,
    };
  } catch (error) {
    logger.error("policy_file_load_error", {
      path: filePath,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * Load all policies from a directory.
 */
function loadPoliciesFromDir(dirPath: string): Map<string, PolicyEntry> {
  const policies = new Map<string, PolicyEntry>();

  if (!existsSync(dirPath)) {
    logger.warning("policy_directory_not_found", { path: dirPath });
    return policies;
  }

  const files = readdirSync(dirPath);

  for (const filename of files) {
    const parsed = extractPolicyId(filename);
    if (!parsed) {
      continue;
    }

    const filePath = join(dirPath, filename);
    const entry = loadPolicyFile(filePath);
    if (entry) {
      policies.set(parsed.id, {
        id: parsed.id,
        ...entry,
      });
      logger.info("policy_loaded", { id: parsed.id, path: filePath });
    }
  }

  return policies;
}

/**
 * Create default policy entry.
 */
function createDefaultPolicyEntry(): PolicyEntry {
  const content = JSON.stringify(DEFAULT_POLICY, null, 2);
  return {
    id: "default",
    policy: DEFAULT_POLICY,
    policyContent: content,
    etag: computeEtag(content),
    lastModified: new Date(),
    filePath: "(built-in)",
    format: "json",
  };
}

// Type for token verifier (from @naylence/runtime)
interface TokenVerifier {
  verify(token: string): Promise<Record<string, unknown>>;
}

/**
 * Create an OAuth2 token verifier from environment configuration.
 */
async function createTokenVerifier(): Promise<TokenVerifier | null> {
  const issuer = process.env[ENV_VAR_OAUTH2_ISSUER];
  if (!issuer) {
    return null;
  }

  try {
    // Dynamically import the token verifier factory from @naylence/runtime
    const { TokenVerifierFactory } = await import("@naylence/runtime");

    const jwksUrl =
      process.env[ENV_VAR_OAUTH2_JWKS_URL] ||
      `${issuer.replace(/\/+$/, "")}/.well-known/jwks.json`;

    const config = {
      type: "JWKSJWTTokenVerifier" as const,
      issuer,
      jwks_url: jwksUrl,
      algorithms: ["RS256"],
    };

    const audience = process.env[ENV_VAR_OAUTH2_AUDIENCE];
    if (audience) {
      (config as Record<string, unknown>).audience = audience;
    }

    const verifier = await TokenVerifierFactory.createTokenVerifier(config);
    logger.info("oauth2_token_verifier_created", { issuer, jwksUrl });
    return verifier;
  } catch (error) {
    logger.error("failed_to_create_token_verifier", {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

/**
 * Authenticate request using OAuth2 JWT verification.
 */
async function authenticateRequest(
  request: FastifyRequest,
  tokenVerifier: TokenVerifier | null,
): Promise<{ authenticated: boolean; error?: string; claims?: Record<string, unknown> }> {
  if (!tokenVerifier) {
    // No auth required (dev mode)
    return { authenticated: true };
  }

  const authHeader = request.headers.authorization;
  if (!authHeader) {
    return { authenticated: false, error: "Missing Authorization header" };
  }

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0]?.toLowerCase() !== "bearer") {
    return { authenticated: false, error: "Invalid Authorization header format" };
  }

  const token = parts[1];
  if (!token) {
    return { authenticated: false, error: "Missing bearer token" };
  }

  try {
    const claims = await tokenVerifier.verify(token);

    // Check required scopes if configured
    const requiredScopesEnv = process.env[ENV_VAR_OAUTH2_REQUIRED_SCOPES];
    if (requiredScopesEnv) {
      const requiredScopes = requiredScopesEnv.split(",").map((s) => s.trim());
      const tokenScopes =
        typeof claims.scope === "string"
          ? claims.scope.split(" ")
          : Array.isArray(claims.scp)
            ? claims.scp
            : [];

      const hasAllScopes = requiredScopes.every((required) =>
        tokenScopes.includes(required),
      );

      if (!hasAllScopes) {
        return {
          authenticated: false,
          error: `Missing required scopes: ${requiredScopes.join(", ")}`,
        };
      }
    }

    logger.debug("jwt_token_verified", { sub: claims.sub });
    return { authenticated: true, claims };
  } catch (error) {
    logger.warning("jwt_verification_failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    return {
      authenticated: false,
      error: error instanceof Error ? error.message : "Token verification failed",
    };
  }
}

/**
 * Create policy router with authorization policy endpoints.
 * Supports fetching policies by ID from: /fame/v1/auth-policies/:policyId
 */
function createPolicyRouter(
  fastify: FastifyInstance,
  state: PolicyServerState,
  tokenVerifier: TokenVerifier | null,
  prefix: string = "/fame/v1",
) {
  const policiesPath = `${prefix}/auth-policies`;

  // List all available policies
  fastify.get(policiesPath, async (request, reply) => {
    const authResult = await authenticateRequest(request, tokenVerifier);
    if (!authResult.authenticated) {
      logger.warning("authentication_failed", { error: authResult.error });
      return reply.status(401).send({
        error: "unauthorized",
        message: authResult.error,
      });
    }

    const policyList = Array.from(state.policies.values()).map((entry) => ({
      id: entry.id,
      lastModified: entry.lastModified.toISOString(),
      format: entry.format,
    }));

    return reply
      .header("Content-Type", "application/json")
      .send({ policies: policyList });
  });

  // Get policy by ID (auto-detect format based on Accept header or original format)
  fastify.get<{ Params: { policyId: string } }>(
    `${policiesPath}/:policyId`,
    async (request, reply) => {
      const authResult = await authenticateRequest(request, tokenVerifier);
      if (!authResult.authenticated) {
        logger.warning("authentication_failed", { error: authResult.error });
        return reply.status(401).send({
          error: "unauthorized",
          message: authResult.error,
        });
      }

      const { policyId } = request.params;
      const entry = state.policies.get(policyId);

      if (!entry) {
        logger.warning("policy_not_found", { policyId });
        return reply.status(404).send({
          error: "not_found",
          message: `Policy '${policyId}' not found`,
          availablePolicies: Array.from(state.policies.keys()),
        });
      }

      // Check ETag for conditional request
      const ifNoneMatch = request.headers["if-none-match"];
      if (ifNoneMatch && ifNoneMatch === entry.etag) {
        logger.debug("returning_304_not_modified", { policyId, etag: entry.etag });
        return reply
          .status(304)
          .header("ETag", entry.etag)
          .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
          .send();
      }

      logger.debug("serving_policy", {
        policyId,
        etag: entry.etag,
        lastModified: entry.lastModified.toISOString(),
      });

      // Determine content type based on Accept header or original format
      const acceptHeader = request.headers.accept || "";
      const isYamlRequest =
        acceptHeader.includes("yaml") || acceptHeader.includes("text/plain");

      let contentType: string;
      let responseBody: string;

      if (isYamlRequest || entry.format === "yaml") {
        contentType = "application/yaml";
        responseBody =
          entry.format === "yaml"
            ? entry.policyContent
            : stringifyYaml(entry.policy);
      } else {
        contentType = "application/json";
        responseBody = JSON.stringify(entry.policy, null, 2);
      }

      return reply
        .header("Content-Type", contentType)
        .header("ETag", entry.etag)
        .header("Last-Modified", entry.lastModified.toUTCString())
        .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
        .send(responseBody);
    },
  );

  // Get policy by ID as YAML
  fastify.get<{ Params: { policyId: string } }>(
    `${policiesPath}/:policyId.yaml`,
    async (request, reply) => {
      const authResult = await authenticateRequest(request, tokenVerifier);
      if (!authResult.authenticated) {
        return reply.status(401).send({
          error: "unauthorized",
          message: authResult.error,
        });
      }

      const { policyId } = request.params;
      const entry = state.policies.get(policyId);

      if (!entry) {
        return reply.status(404).send({
          error: "not_found",
          message: `Policy '${policyId}' not found`,
        });
      }

      const ifNoneMatch = request.headers["if-none-match"];
      if (ifNoneMatch && ifNoneMatch === entry.etag) {
        return reply
          .status(304)
          .header("ETag", entry.etag)
          .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
          .send();
      }

      const yamlContent =
        entry.format === "yaml" ? entry.policyContent : stringifyYaml(entry.policy);

      return reply
        .header("Content-Type", "application/yaml")
        .header("ETag", entry.etag)
        .header("Last-Modified", entry.lastModified.toUTCString())
        .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
        .send(yamlContent);
    },
  );

  // Get policy by ID as JSON
  fastify.get<{ Params: { policyId: string } }>(
    `${policiesPath}/:policyId.json`,
    async (request, reply) => {
      const authResult = await authenticateRequest(request, tokenVerifier);
      if (!authResult.authenticated) {
        return reply.status(401).send({
          error: "unauthorized",
          message: authResult.error,
        });
      }

      const { policyId } = request.params;
      const entry = state.policies.get(policyId);

      if (!entry) {
        return reply.status(404).send({
          error: "not_found",
          message: `Policy '${policyId}' not found`,
        });
      }

      const ifNoneMatch = request.headers["if-none-match"];
      if (ifNoneMatch && ifNoneMatch === entry.etag) {
        return reply
          .status(304)
          .header("ETag", entry.etag)
          .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
          .send();
      }

      return reply
        .header("Content-Type", "application/json")
        .header("ETag", entry.etag)
        .header("Last-Modified", entry.lastModified.toUTCString())
        .header("Cache-Control", "public, max-age=60, stale-while-revalidate=300")
        .send(entry.policy);
    },
  );

  // Health check
  fastify.get("/health", async () => {
    return {
      status: "healthy",
      service: "auth-policy-server",
      policyDirectory: state.policyDir || "(using defaults)",
      policyCount: state.policies.size,
      policies: Array.from(state.policies.keys()),
    };
  });
}

/**
 * Create Fastify application with policy server.
 */
async function createApp(): Promise<{
  app: FastifyInstance;
  state: PolicyServerState;
}> {
  const fastify = Fastify({
    logger: false,
  });

  // Load policies from directory or use default
  const policyDir = process.env[ENV_VAR_FAME_POLICY_DIR];

  const state: PolicyServerState = {
    policyDir,
    policies: new Map(),
  };

  if (policyDir && existsSync(policyDir)) {
    state.policies = loadPoliciesFromDir(policyDir);

    // Watch directory for changes
    watch(policyDir, (eventType, filename) => {
      if (!filename) return;

      const parsed = extractPolicyId(filename);
      if (!parsed) return;

      const filePath = join(policyDir, filename);

      if (eventType === "rename") {
        // File added or removed
        if (existsSync(filePath)) {
          const entry = loadPolicyFile(filePath);
          if (entry) {
            state.policies.set(parsed.id, { id: parsed.id, ...entry });
            logger.info("policy_added", { id: parsed.id, path: filePath });
          }
        } else {
          state.policies.delete(parsed.id);
          logger.info("policy_removed", { id: parsed.id });
        }
      } else if (eventType === "change") {
        // File modified
        const entry = loadPolicyFile(filePath);
        if (entry) {
          state.policies.set(parsed.id, { id: parsed.id, ...entry });
          logger.info("policy_reloaded", { id: parsed.id, path: filePath });
        }
      }
    });

    logger.info("watching_policy_directory", { path: policyDir });
  }

  // Always add a default policy
  if (state.policies.size === 0) {
    state.policies.set("default", createDefaultPolicyEntry());
    logger.info("using_default_policy", {
      reason: policyDir ? "no_policies_found_in_directory" : "no_directory_specified",
    });
  }

  // Create OAuth2 token verifier if configured
  const tokenVerifier = await createTokenVerifier();

  // Register policy router
  createPolicyRouter(fastify, state, tokenVerifier);

  if (tokenVerifier) {
    logger.info("oauth2_jwt_auth_enabled", {
      issuer: process.env[ENV_VAR_OAUTH2_ISSUER],
    });
  } else {
    logger.warning("auth_disabled", {
      message: "Set FAME_OAUTH2_ISSUER to enable OAuth2 JWT authentication",
    });
  }

  return { app: fastify, state };
}

async function main() {
  try {
    const { app, state } = await createApp();

    const host = process.env[ENV_VAR_FAME_APP_HOST] || "0.0.0.0";
    const port = parseInt(process.env[ENV_VAR_FAME_APP_PORT] || "8099", 10);

    await app.listen({ host, port });

    const issuer = process.env[ENV_VAR_OAUTH2_ISSUER];

    logger.info("auth_policy_server_started", { host, port });
    console.log(`\n📍 Auth Policy Server listening on http://${host}:${port}`);
    console.log(`📋 List policies: http://${host}:${port}/fame/v1/auth-policies`);
    console.log(`📋 Get policy: http://${host}:${port}/fame/v1/auth-policies/{policy_id}`);
    console.log(`📋 Get as YAML: http://${host}:${port}/fame/v1/auth-policies/{policy_id}.yaml`);
    console.log(`📋 Get as JSON: http://${host}:${port}/fame/v1/auth-policies/{policy_id}.json`);
    console.log(`🔍 Health check: http://${host}:${port}/health`);
    if (state.policyDir) {
      console.log(`📁 Serving policies from: ${state.policyDir}`);
      console.log(`📁 Policy files should be named: policy-{id}.yaml or policy-{id}.json`);
    } else {
      console.log(
        `⚠️  No policy directory set (set FAME_POLICY_DIR to serve custom policies)`,
      );
    }
    console.log(`📊 Loaded ${state.policies.size} policy(ies): ${Array.from(state.policies.keys()).join(", ")}`);
    if (issuer) {
      console.log(`🔐 OAuth2 JWT authentication enabled (issuer: ${issuer})`);
    } else {
      console.log(`⚠️  No authentication (set FAME_OAUTH2_ISSUER to enable)`);
    }
    console.log("");
  } catch (error) {
    logger.error("auth_policy_server_startup_failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }
}

export {
  createApp,
  main,
  loadPoliciesFromDir,
  loadPolicyFile,
  extractPolicyId,
  computeEtag,
  DEFAULT_POLICY,
  type PolicyEntry,
  type PolicyServerState,
};

const isTopLevelInvocation = (() => {
  if (typeof process === "undefined") {
    return false;
  }
  const entry = process.argv[1] ?? null;
  if (!entry) {
    return false;
  }
  try {
    const entryPath = resolveToRealPath(entry);
    if (!entryPath) {
      return false;
    }
    return /(?:^|[\\/])auth-policy-server\.js$/u.test(entryPath);
  } catch {
    return false;
  }
})();

if (isTopLevelInvocation) {
  void main();
}

function resolveToRealPath(pathLike: string): string | null {
  try {
    return realpathSync(pathLike);
  } catch {
    try {
      return realpathSync.native?.(pathLike) ?? resolve(pathLike);
    } catch {
      return resolve(pathLike);
    }
  }
}
