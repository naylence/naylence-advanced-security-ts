/**
 * CA Server - Certificate Authority HTTP endpoint
 *
 * Provides certificate issuance via HTTP using Fastify.
 * Mirrors the Python ca_server.py implementation.
 */

import { sha256 } from "@noble/hashes/sha256.js";
import Fastify from "fastify";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import type { FastifyInstance } from "fastify";
import { CAServiceFactory } from "./ca-service-factory.js";
import type { CAService, TrustBundleDocument } from "./ca-types.js";

// Simple console logger for CA server
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

const ENV_VAR_FAME_APP_HOST = "FAME_APP_HOST";
const ENV_VAR_FAME_APP_PORT = "FAME_APP_PORT";

interface CSRRequest {
  csr_pem: string;
  requester_id: string;
  physical_path?: string;
  logicals?: string[];
}

interface CertificateIssuanceResponse {
  certificate_pem: string;
  certificate_chain_pem?: string;
  expires_at: string;
}

/**
 * Create CA router with certificate signing endpoint.
 * Mirrors Python's create_ca_router functionality.
 */
function createCaRouter(
  fastify: FastifyInstance,
  caService: CAService,
  prefix: string = "/fame/v1/ca",
) {
  // Certificate signing endpoint
  fastify.post<{ Body: CSRRequest }>(
    `${prefix}/sign`,
    {
      schema: {
        body: {
          type: "object",
          required: ["csr_pem", "requester_id"],
          properties: {
            csr_pem: { type: "string" },
            requester_id: { type: "string" },
            physical_path: { type: "string" },
            logicals: { type: "array", items: { type: "string" } },
          },
        },
      },
    },
    async (request, reply) => {
      try {
        const csrRequest = request.body;

        if (!csrRequest || !csrRequest.requester_id) {
          return reply.status(400).send({
            error: "invalid_request",
            message: "CSR must include requester_id",
          });
        }

        logger.debug("ca_cert_request_received", {
          requester_id: csrRequest.requester_id,
          physical_path: csrRequest.physical_path,
          logicals: csrRequest.logicals,
        });

        // Authenticate if authorizer is configured
        if (caService.authorizer) {
          // TODO: Implement authentication when authorizer interface is defined
          logger.warning("authentication_not_yet_implemented", {
            authorizer_configured: true,
          });
        }

        // Convert snake_case request to camelCase for TypeScript interface
        const csrForService = {
          csrPem: csrRequest.csr_pem,
          requesterId: csrRequest.requester_id,
          physicalPath: csrRequest.physical_path,
          logicals: csrRequest.logicals,
        };

        // Issue certificate
        const result = await caService.issueCertificate(csrForService);

        const response: CertificateIssuanceResponse = {
          certificate_pem: result.certificatePem,
          certificate_chain_pem: result.certificateChainPem,
          expires_at: result.expiresAt,
        };

        return reply.send(response);
      } catch (error) {
        logger.error("ca_cert_issuance_failed", {
          error: error instanceof Error ? error.message : String(error),
        });

        return reply.status(500).send({
          error: "issuance_failed",
          message: error instanceof Error ? error.message : "Unknown error",
        });
      }
    },
  );

  // Health check
  fastify.get("/health", async () => {
    return { status: "healthy", service: "ca-server" };
  });

  const trustBundlePath = "/.well-known/naylence/trust-bundle.json";

  fastify.get(trustBundlePath, async (request, reply) => {
    const bundle = await caService.getTrustBundle();
    if (!bundle) {
      return reply.status(404).send({
        error: "trust_bundle_unavailable",
      });
    }

    const payload = JSON.stringify(bundle);
    const etag = `"${computeEtag(payload)}"`;
    const requestEtag = request.headers["if-none-match"];

    if (typeof requestEtag === "string" && requestEtag.replace(/W\//u, "") === etag.replace(/W\//u, "")) {
      return reply
        .status(304)
        .header("ETag", etag)
        .header("Cache-Control", trustBundleCacheControl())
        .send();
    }

    return reply
      .header("Content-Type", "application/json")
      .header("Cache-Control", trustBundleCacheControl())
      .header("ETag", etag)
      .send(bundle satisfies TrustBundleDocument);
  });
}

/**
 * Create Fastify application with CA service lifespan management.
 * Mirrors Python's FastAPI lifespan pattern.
 */
async function createApp(): Promise<{
  app: FastifyInstance;
  caService: CAService;
}> {
  // Disable Fastify's built-in logger to avoid configuration conflicts
  const fastify = Fastify({
    logger: false,
  });

  // Register advanced security factories (including CA service factory)
  const { registerAdvancedSecurityPluginFactories } = await import(
    "../../../../plugin.js"
  );
  await registerAdvancedSecurityPluginFactories();

  // Create CA service (mirrors Python's lifespan startup)
  const caService = await CAServiceFactory.createCAService();

  // Register CA router
  createCaRouter(fastify, caService);

  return { app: fastify, caService };
}

async function main() {
  try {
    const { app } = await createApp();

    const host = process.env[ENV_VAR_FAME_APP_HOST] || "0.0.0.0";
    const port = parseInt(process.env[ENV_VAR_FAME_APP_PORT] || "8098", 10);

    await app.listen({ host, port });

    logger.info("ca_server_started", { host, port });
    console.log(`\n📍 CA Server listening on http://${host}:${port}`);
    console.log(
      `🔐 Certificate endpoint: http://${host}:${port}/fame/v1/ca/sign\n`,
    );
  } catch (error) {
    logger.error("ca_server_startup_failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }
}

export { createApp, main };

const isTopLevelInvocation = (() => {
  if (typeof process === "undefined") {
    return false;
  }
  const entry = process.argv[1] ?? null;
  if (!entry) {
    if (process.env.FAME_CA_DEBUG === "1") {
      console.log(
        "[CA DEBUG] missing process argv entry",
        JSON.stringify({ argv: process.argv }),
      );
    }
    return false;
  }
  try {
    const entryPath = resolveToRealPath(entry);
    if (!entryPath) {
      if (process.env.FAME_CA_DEBUG === "1") {
        console.log(
          "[CA DEBUG] failed to resolve entry path",
          JSON.stringify({ entry }),
        );
      }
      return false;
    }
    if (process.env.FAME_CA_DEBUG === "1") {
      console.log(
        "[CA DEBUG] invocation check",
        JSON.stringify({
          argv: process.argv,
          entryPath,
        }),
      );
    }
    return /(?:^|[\\/])ca-server\.js$/u.test(entryPath);
  } catch (error) {
    if (process.env.FAME_CA_DEBUG === "1") {
      console.log(
        "[CA DEBUG] invocation check error",
        JSON.stringify({ error: error instanceof Error ? error.message : String(error) }),
      );
    }
    return false;
  }
})();

if (isTopLevelInvocation) {
  void main();
}

function computeEtag(payload: string): string {
  const encoder = new TextEncoder();
  const digest = sha256(encoder.encode(payload));
  return Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function trustBundleCacheControl(): string {
  return "public, max-age=3600, stale-while-revalidate=86400";
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
