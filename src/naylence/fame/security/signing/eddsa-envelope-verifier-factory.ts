import type { EnvelopeVerifier } from "@naylence/runtime";
import {
  ENVELOPE_VERIFIER_FACTORY_BASE_TYPE,
  EnvelopeVerifierFactory,
  SigningConfigClass,
  type EnvelopeVerifierConfig,
  type KeyProvider,
} from "@naylence/runtime";

import {
  EdDSAEnvelopeVerifier,
  type EdDSAEnvelopeVerifierOptions,
  type SigningConfigInstance,
} from "./eddsa-envelope-verifier.js";

export interface EdDSAEnvelopeVerifierConfig extends EnvelopeVerifierConfig {
  readonly type: "EdDSAEnvelopeVerifier";
}

export const FACTORY_META = {
  base: ENVELOPE_VERIFIER_FACTORY_BASE_TYPE,
  key: "EdDSAEnvelopeVerifier",
  isDefault: true,
  priority: 100,
} as const;

type SigningConfig = SigningConfigInstance;

export class AdvancedEdDSAEnvelopeVerifierFactory extends EnvelopeVerifierFactory<EdDSAEnvelopeVerifierConfig> {
  public readonly type = "EdDSAEnvelopeVerifier";
  public readonly isDefault = true;
  public readonly priority = 100;

  public async create(
    _config?: EdDSAEnvelopeVerifierConfig | Record<string, unknown> | null,
    keyProvider?: KeyProvider | null,
    signingConfig?: SigningConfig | null,
    options: EdDSAEnvelopeVerifierOptions = {},
  ): Promise<EnvelopeVerifier> {
    if (!keyProvider) {
      throw new Error("EdDSAEnvelopeVerifierFactory requires a key provider");
    }

    const resolved: EdDSAEnvelopeVerifierOptions = {
      signingConfig:
        options.signingConfig ?? signingConfig ?? new SigningConfigClass(),
    };

    return new EdDSAEnvelopeVerifier(keyProvider, resolved);
  }
}

export default AdvancedEdDSAEnvelopeVerifierFactory;
