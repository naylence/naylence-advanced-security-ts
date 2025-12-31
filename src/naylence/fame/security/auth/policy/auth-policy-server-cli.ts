#!/usr/bin/env node
/**
 * Auth Policy Server CLI Entry Point
 *
 * Development server for serving authorization policies over HTTP.
 * Useful for testing HttpAuthorizationPolicySource.
 *
 * Environment variables:
 *   FAME_APP_HOST - Host to bind to (default: 0.0.0.0)
 *   FAME_APP_PORT - Port to listen on (default: 8099)
 *   FAME_POLICY_FILE - Path to policy file (YAML or JSON)
 *   FAME_POLICY_BEARER_TOKEN - Bearer token for authentication
 *   FAME_LOG_LEVEL - Log level (debug, info, warning, error)
 *
 * Usage:
 *   npx naylence-policy-server
 *   FAME_POLICY_FILE=./policy.yaml FAME_POLICY_BEARER_TOKEN=secret npx naylence-policy-server
 */

import { pathToFileURL } from "node:url";

import { main } from "./auth-policy-server.js";

function isDirectExecution(): boolean {
  if (typeof process === "undefined") {
    return false;
  }

  const entry = process.argv?.[1];
  if (typeof entry !== "string" || entry.length === 0) {
    return false;
  }

  const entryUrl = pathToFileURL(entry).href;
  return import.meta.url === entryUrl;
}

function registerSignalHandlers(): void {
  const handleShutdown = (signal: NodeJS.Signals) => {
    console.log("[INFO] auth_policy_server_shutting_down", { signal });
    process.exit(0);
  };

  process.on("SIGTERM", () => handleShutdown("SIGTERM"));
  process.on("SIGINT", () => handleShutdown("SIGINT"));
}

if (isDirectExecution()) {
  registerSignalHandlers();

  main().catch((error) => {
    console.error("Fatal error:", error);
    process.exit(1);
  });
}
