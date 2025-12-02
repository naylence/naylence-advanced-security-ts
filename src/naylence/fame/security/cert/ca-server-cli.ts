#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import { main } from "./ca-server.js";

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
    console.log("[INFO] ca_server_shutting_down", { signal });
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
