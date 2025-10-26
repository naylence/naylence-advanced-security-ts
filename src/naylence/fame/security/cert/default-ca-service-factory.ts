/**
 * Factory for creating DefaultCAService instances.
 *
 * Provides the default CA service implementation with environment variable support.
 */

import type { ResourceConfig } from "@naylence/factory";
import { AbstractResourceFactory } from "@naylence/factory";
import type { Authorizer } from "./ca-types.js";
import type { CAService } from "./ca-types.js";
import { DefaultCAService } from "./default-ca-service.js";

/**
 * Configuration for DefaultCAService.
 */
export interface DefaultCAServiceConfig extends ResourceConfig {
  type: "DefaultCAService";

  /** Root CA certificate in PEM format (optional, can use environment variables) */
  caCertPem?: string;
  ca_cert_pem?: string;

  /** Root CA private key in PEM format (optional, can use environment variables) */
  caKeyPem?: string;
  ca_key_pem?: string;

  /** Complete intermediate CA chain in PEM format (optional) */
  intermediateChainPem?: string;
  intermediate_chain_pem?: string;

  /** Certificate to use for signing (leaf of the chain, optional) */
  signingCertPem?: string;
  signing_cert_pem?: string;

  /** Private key for the signing certificate (optional) */
  signingKeyPem?: string;
  signing_key_pem?: string;

  /** Authorizer configuration (optional) */
  authorizer?: unknown;
}

/**
 * Factory metadata for DefaultCAServiceFactory.
 */
export const FACTORY_META = {
  base: "CAServiceFactory",
  key: "DefaultCAService",
} as const;

/**
 * Normalize configuration from snake_case or camelCase to standard format.
 */
function normalizeConfig(
  config?: DefaultCAServiceConfig | Record<string, unknown> | null,
): DefaultCAServiceConfig {
  if (!config) {
    return { type: "DefaultCAService" };
  }

  const { type: _ignoredType, ...rest } = config as Record<string, unknown>;
  return {
    ...rest,
    type: "DefaultCAService",
  } as DefaultCAServiceConfig;
}

/**
 * Factory for creating DefaultCAService instances.
 */
export class DefaultCAServiceFactory extends AbstractResourceFactory<
  CAService,
  DefaultCAServiceConfig
> {
  public readonly type = "DefaultCAService";
  public readonly isDefault = true;
  public readonly priority = 100;

  /**
   * Create a DefaultCAService instance.
   *
   * @param config - DefaultCAService configuration
   * @returns Configured DefaultCAService instance
   */
  public async create(
    config?: DefaultCAServiceConfig | Record<string, unknown> | null,
    ..._factoryArgs: unknown[]
  ): Promise<CAService> {
    const normalizedConfig = normalizeConfig(config);

    // Extract configuration with snake_case fallbacks
    const caCertPem =
      normalizedConfig.caCertPem ?? normalizedConfig.ca_cert_pem;
    const caKeyPem = normalizedConfig.caKeyPem ?? normalizedConfig.ca_key_pem;
    const intermediateChainPem =
      normalizedConfig.intermediateChainPem ??
      normalizedConfig.intermediate_chain_pem;
    const signingCertPem =
      normalizedConfig.signingCertPem ?? normalizedConfig.signing_cert_pem;
    const signingKeyPem =
      normalizedConfig.signingKeyPem ?? normalizedConfig.signing_key_pem;

    // TODO: Create authorizer from config when AuthorizerFactory is available
    const authorizer: Authorizer | undefined = undefined;

    return new DefaultCAService({
      caCertPem,
      caKeyPem,
      intermediateChainPem,
      signingCertPem,
      signingKeyPem,
      authorizer,
    });
  }
}

export default DefaultCAServiceFactory;
