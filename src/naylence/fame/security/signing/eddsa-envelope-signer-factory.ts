import type { EnvelopeSigner } from "@naylence/runtime";
import {
  ENVELOPE_SIGNER_FACTORY_BASE_TYPE,
  EnvelopeSignerFactory,
  type EnvelopeSignerConfig,
} from "@naylence/runtime";

import type { EdDSAEnvelopeSignerOptions } from "naylence-runtime/naylence/fame/security/signing/eddsa-envelope-signer.js";

export interface EdDSAEnvelopeSignerConfig extends EnvelopeSignerConfig {
  readonly type: "EdDSAEnvelopeSigner";
}

export const FACTORY_META = {
  base: ENVELOPE_SIGNER_FACTORY_BASE_TYPE,
  key: "EdDSAEnvelopeSigner",
  isDefault: true,
  priority: 100,
} as const;

type EdDSAEnvelopeSignerModule =
  typeof import("naylence-runtime/naylence/fame/security/signing/eddsa-envelope-signer.js");

let eddsaEnvelopeSignerModulePromise: Promise<EdDSAEnvelopeSignerModule> | null =
  null;

async function getEdDSAEnvelopeSignerModule(): Promise<EdDSAEnvelopeSignerModule> {
  if (!eddsaEnvelopeSignerModulePromise) {
    eddsaEnvelopeSignerModulePromise = import(
      "naylence-runtime/naylence/fame/security/signing/eddsa-envelope-signer.js"
    );
  }

  return eddsaEnvelopeSignerModulePromise;
}

export class AdvancedEdDSAEnvelopeSignerFactory extends EnvelopeSignerFactory<EdDSAEnvelopeSignerConfig> {
  public readonly type = "EdDSAEnvelopeSigner";
  public readonly isDefault = true;
  public readonly priority = 100;

  public async create(
    _config?: EdDSAEnvelopeSignerConfig | Record<string, unknown> | null,
    options?: EdDSAEnvelopeSignerOptions | null,
  ): Promise<EnvelopeSigner> {
    const resolved: EdDSAEnvelopeSignerOptions = {
      cryptoProvider: options?.cryptoProvider ?? null,
      signingConfig: options?.signingConfig ?? null,
      privateKeyPem: options?.privateKeyPem,
      keyId: options?.keyId,
    };

    const { EdDSAEnvelopeSigner } = await getEdDSAEnvelopeSignerModule();

    return new EdDSAEnvelopeSigner(resolved);
  }
}

export default AdvancedEdDSAEnvelopeSignerFactory;
