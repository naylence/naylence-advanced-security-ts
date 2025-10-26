declare module "@naylence/runtime/dist/esm/naylence/fame/security/signing/eddsa-signer-verifier.js" {
  export function canonicalJson(value: unknown): string;
  export function decodeBase64Url(value: string): Uint8Array;
  export function frameDigest(frame: unknown): string;
  export function immutableHeaders(envelope: unknown): Record<string, unknown>;
}

declare module "@naylence/runtime/dist/esm/naylence/fame/security/signing/eddsa-utils.js" {
  export function encodeUtf8(value: string): Uint8Array;
}

declare module "@naylence/runtime/naylence/fame/security/signing/eddsa-signer-verifier.js" {
  export function canonicalJson(value: unknown): string;
  export function decodeBase64Url(value: string): Uint8Array;
  export function frameDigest(frame: unknown): string;
  export function immutableHeaders(envelope: unknown): Record<string, unknown>;
}

declare module "@naylence/runtime/naylence/fame/security/signing/eddsa-utils.js" {
  export function encodeUtf8(value: string): Uint8Array;
}

declare module "@naylence/runtime/dist/esm/naylence/fame/security/signing/eddsa-envelope-signer.js" {
  import type { FameEnvelope } from "@naylence/core";

  export interface EdDSAEnvelopeSignerOptions {
    readonly cryptoProvider?: unknown | null;
    readonly signingConfig?: unknown | null;
    readonly privateKeyPem?: string;
    readonly keyId?: string;
  }

  export class EdDSAEnvelopeSigner {
    public constructor(options?: EdDSAEnvelopeSignerOptions);
    public signEnvelope(
      envelope: FameEnvelope,
      context: { physicalPath: string },
    ): FameEnvelope;
  }
}

declare module "@naylence/runtime/naylence/fame/security/signing/eddsa-envelope-signer.js" {
  import type { FameEnvelope } from "@naylence/core";

  export interface EdDSAEnvelopeSignerOptions {
    readonly cryptoProvider?: unknown | null;
    readonly signingConfig?: unknown | null;
    readonly privateKeyPem?: string;
    readonly keyId?: string;
  }

  export class EdDSAEnvelopeSigner {
    public constructor(options?: EdDSAEnvelopeSignerOptions);
    public signEnvelope(
      envelope: FameEnvelope,
      context: { physicalPath: string },
    ): FameEnvelope;
  }
}
