import { sha256 } from "@noble/hashes/sha2.js";
import { X509Certificate } from "@peculiar/x509";

import type { TrustAnchor } from "./trust-store-provider.js";

const PEM_HEADER = "-----BEGIN CERTIFICATE-----";

function normalizeLineEndings(value: string): string {
  return value.replace(/\r\n?/gu, "\n");
}

export function isPem(value: string | null | undefined): value is string {
  return typeof value === "string" && value.includes(PEM_HEADER);
}

export function extractPemBlocks(value: string): string[] {
  if (!isPem(value)) {
    return [];
  }

  const normalized = normalizeLineEndings(value).trim();
  const pattern = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/gu;
  const matches = normalized.match(pattern);
  if (!matches) {
    return [];
  }

  return matches.map((block) => `${block.trim()}\n`);
}

export function pemChainToAnchors(pem: string): TrustAnchor[] {
  const anchors: TrustAnchor[] = [];
  for (const block of extractPemBlocks(pem)) {
    anchors.push({ pem: block });
  }
  return anchors;
}

export function anchorsToPem(anchors: Iterable<TrustAnchor>): string {
  const blocks: string[] = [];
  for (const anchor of anchors) {
    if (isPem(anchor.pem)) {
      blocks.push(normalizePem(anchor.pem));
    }
  }
  return blocks.join("\n");
}

export function normalizePem(pem: string): string {
  const blocks = extractPemBlocks(pem);
  return blocks.join("\n");
}

export function computeSpkiSha256(pem: string): string | null {
  try {
    const cert = new X509Certificate(pem);
    const publicKey = (cert as unknown as {
      publicKey?: { rawData?: ArrayBuffer };
    }).publicKey;

    if (!publicKey?.rawData) {
      return null;
    }

    const der = new Uint8Array(publicKey.rawData);
    const digest = sha256(der);
    return toBase64Url(digest);
  } catch {
    return null;
  }
}

export function withComputedSpki(
  anchors: readonly TrustAnchor[],
): TrustAnchor[] {
  return anchors.map((anchor) => {
    if (anchor.spkiSha256) {
      return anchor;
    }

    const spki = computeSpkiSha256(anchor.pem);
    if (!spki) {
      return anchor;
    }

    return { ...anchor, spkiSha256: spki };
  });
}

export function dataUriToPem(dataUri: string): string | null {
  const match = /^data:(?<mime>[^;,]+)?(?:;charset=[^;,]+)?;base64,(?<data>.+)$/u.exec(
    dataUri,
  );
  if (!match?.groups?.data) {
    return null;
  }

  const decodedBytes = base64ToBytes(match.groups.data);
  const decoded = bytesToUtf8(decodedBytes);
  return normalizePem(decoded);
}

export function toBase64Url(data: Uint8Array): string {
  let base64: string;
  if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(data).toString("base64");
  } else {
    base64 = btoa(String.fromCharCode(...Array.from(data)));
  }
  return base64.replace(/=/gu, "").replace(/\+/gu, "-").replace(/\//gu, "_");
}

export function parsePemOrThrow(pem: string): string {
  const normalized = normalizePem(pem);
  if (!normalized) {
    throw new Error("Invalid PEM content");
  }
  return normalized;
}

function base64ToBytes(data: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(data, "base64"));
  }

  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToUtf8(data: Uint8Array): string {
  if (typeof TextDecoder !== "undefined") {
    return new TextDecoder().decode(data);
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("utf8");
  }

  let result = "";
  for (const value of data) {
    result += String.fromCharCode(value);
  }
  return result;
}
