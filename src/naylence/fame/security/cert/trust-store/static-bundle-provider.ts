import {
  anchorsToPem,
  normalizePem,
  pemChainToAnchors,
  withComputedSpki,
  dataUriToPem,
} from "./anchor-utils.js";
import type { TrustAnchor, TrustStoreProvider } from "./trust-store-provider.js";

export interface StaticBundleProviderOptions {
  readonly label?: string;
}

export class StaticBundleProvider implements TrustStoreProvider {
  private readonly anchors: readonly TrustAnchor[];
  private readonly pemChain: string;

  public constructor(anchors: Iterable<TrustAnchor>) {
    const normalized = Array.from(anchors).map((anchor) => ({
      ...anchor,
      pem: normalizePem(anchor.pem),
    }));
    this.anchors = withComputedSpki(normalized);
    this.pemChain = anchorsToPem(this.anchors);
  }

  public async getRoots(): Promise<readonly TrustAnchor[]> {
    return this.anchors;
  }

  public async getTrustStorePem(): Promise<string> {
    if (!this.pemChain || this.pemChain.trim().length === 0) {
      throw new Error("Static trust bundle is empty");
    }
    return this.pemChain;
  }
}

export async function loadPemFromFile(path: string): Promise<string> {
  if (!isNodeEnvironment()) {
    throw new Error("File-based trust bundles are only supported in Node environments");
  }

  const fs = await import("node:fs/promises");
  const contents = await fs.readFile(path, "utf8");
  return normalizePem(contents);
}

export function createProviderFromPem(pem: string): StaticBundleProvider {
  return new StaticBundleProvider(pemChainToAnchors(pem));
}

export function createProviderFromDataUri(dataUri: string): StaticBundleProvider {
  const pem = dataUriToPem(dataUri);
  if (!pem) {
    throw new Error("Invalid data URI for trust bundle");
  }
  return createProviderFromPem(pem);
}

function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions !== "undefined" &&
    typeof process.versions.node === "string"
  );
}
