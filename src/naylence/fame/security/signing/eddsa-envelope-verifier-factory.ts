import type { EnvelopeVerifier } from "@naylence/runtime";
import {
  ENVELOPE_VERIFIER_FACTORY_BASE_TYPE,
  EnvelopeVerifierFactory,
  SigningConfigClass,
  TrustStoreProviderFactory,
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
    ...factoryArgs: unknown[]
  ): Promise<EnvelopeVerifier> {
    if (!keyProvider) {
      throw new Error("EdDSAEnvelopeVerifierFactory requires a key provider");
    }

    // Extract options from factoryArgs (third parameter after keyProvider and signingConfig)
    const options = (factoryArgs[0] as EdDSAEnvelopeVerifierOptions | undefined) ?? {};

    let trustStoreProvider = options.trustStoreProvider ?? null;
    if (!trustStoreProvider) {
      trustStoreProvider = await TrustStoreProviderFactory.createTrustStoreProvider();
    }

    const resolved: EdDSAEnvelopeVerifierOptions = {
      signingConfig:
        options.signingConfig ?? signingConfig ?? new SigningConfigClass(),
      trustStoreProvider,
    };

    return new EdDSAEnvelopeVerifier(keyProvider, resolved);
  }
}

export default AdvancedEdDSAEnvelopeVerifierFactory;
