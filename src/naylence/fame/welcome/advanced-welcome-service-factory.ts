import type {
  AuthorizerConfig,
  TokenIssuerConfig,
  NodePlacementConfig,
  TransportProvisionerConfig,
  DefaultWelcomeServiceConfig,
} from "@naylence/runtime";
import {
  AuthorizerFactory,
  TokenIssuerFactory,
  NodePlacementStrategyFactory,
  TransportProvisionerFactory,
  WelcomeServiceFactory,
  WELCOME_SERVICE_FACTORY_BASE_TYPE,
  type WelcomeService,
} from "@naylence/runtime";

import {
  AdvancedWelcomeService,
  type AdvancedWelcomeServiceOptions,
} from "./advanced-welcome-service.js";

export interface AdvancedWelcomeServiceConfig
  extends Omit<DefaultWelcomeServiceConfig, "type"> {
  type: "AdvancedWelcomeService";
  caServiceUrl?: string | null;
  ca_service_url?: string | null;
}

interface NormalizedAdvancedWelcomeConfig {
  placementConfig?: NodePlacementConfig | Record<string, unknown> | null;
  transportConfig?: TransportProvisionerConfig | Record<string, unknown> | null;
  tokenIssuerConfig?: TokenIssuerConfig | Record<string, unknown> | null;
  authorizerConfig?: AuthorizerConfig | Record<string, unknown> | null;
  ttlSec?: number;
  caServiceUrl: string;
}

export const FACTORY_META = {
  base: WELCOME_SERVICE_FACTORY_BASE_TYPE,
  key: "AdvancedWelcomeService",
  priority: 100,
  isDefault: true,
} as const;

export class AdvancedWelcomeServiceFactory extends WelcomeServiceFactory<AdvancedWelcomeServiceConfig> {
  public readonly type = FACTORY_META.key;
  public readonly isDefault = FACTORY_META.isDefault;
  public readonly priority = FACTORY_META.priority;

  public async create(
    config?: AdvancedWelcomeServiceConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<WelcomeService> {
    const normalized = normalizeConfig(config);

    // Crypto provider should be passed from upstream (node-welcome-server)
    // Do not create it here - downstream components should use what's passed in factoryArgs

    const placementStrategy =
      await NodePlacementStrategyFactory.createNodePlacementStrategy(
        normalized.placementConfig ?? null,
        factoryArgs.length > 0 ? { factoryArgs } : undefined,
      );

    const transportProvisioner =
      await TransportProvisionerFactory.createTransportProvisioner(
        normalized.transportConfig ?? null,
        factoryArgs.length > 0 ? { factoryArgs } : undefined,
      );

    const tokenIssuer = await TokenIssuerFactory.createTokenIssuer(
      normalized.tokenIssuerConfig ?? null,
      factoryArgs.length > 0 ? { factoryArgs } : undefined,
    );

    let authorizer = null;
    if (normalized.authorizerConfig) {
      authorizer =
        (await AuthorizerFactory.createAuthorizer(normalized.authorizerConfig, {
          factoryArgs,
        })) ?? null;
    }

    const options: AdvancedWelcomeServiceOptions = {
      placementStrategy,
      transportProvisioner,
      tokenIssuer,
      authorizer,
      caServiceUrl: normalized.caServiceUrl,
    };

    if (normalized.ttlSec !== undefined) {
      options.ttlSec = normalized.ttlSec;
    }

    return new AdvancedWelcomeService(options);
  }
}

function normalizeConfig(
  config?: AdvancedWelcomeServiceConfig | Record<string, unknown> | null,
): NormalizedAdvancedWelcomeConfig {
  if (!config) {
    throw new Error("AdvancedWelcomeService requires configuration");
  }

  const source = config as AdvancedWelcomeServiceConfig &
    Record<string, unknown>;

  const ttlCandidate =
    typeof source.ttlSec === "number"
      ? source.ttlSec
      : typeof source.ttl_sec === "number"
        ? source.ttl_sec
        : undefined;

  const caServiceUrlCandidate =
    typeof source.caServiceUrl === "string" &&
    source.caServiceUrl.trim().length > 0
      ? source.caServiceUrl.trim()
      : typeof source.ca_service_url === "string" &&
          source.ca_service_url.trim().length > 0
        ? source.ca_service_url.trim()
        : undefined;

  if (!caServiceUrlCandidate) {
    throw new Error(
      "AdvancedWelcomeService configuration requires caServiceUrl",
    );
  }

  const normalized: NormalizedAdvancedWelcomeConfig = {
    caServiceUrl: caServiceUrlCandidate,
  };

  if (source.placement !== undefined) {
    normalized.placementConfig =
      (source.placement as
        | NodePlacementConfig
        | Record<string, unknown>
        | null) ?? null;
  }

  if (source.transport !== undefined) {
    normalized.transportConfig =
      (source.transport as
        | TransportProvisionerConfig
        | Record<string, unknown>
        | null) ?? null;
  }

  const tokenIssuerConfig =
    source.tokenIssuer !== undefined
      ? source.tokenIssuer
      : source.token_issuer !== undefined
        ? source.token_issuer
        : undefined;

  if (tokenIssuerConfig !== undefined) {
    normalized.tokenIssuerConfig =
      (tokenIssuerConfig as
        | TokenIssuerConfig
        | Record<string, unknown>
        | null) ?? null;
  }

  if (source.authorizer !== undefined) {
    normalized.authorizerConfig =
      (source.authorizer as
        | AuthorizerConfig
        | Record<string, unknown>
        | null) ?? null;
  }

  if (ttlCandidate !== undefined && Number.isFinite(ttlCandidate)) {
    normalized.ttlSec = ttlCandidate;
  }

  return normalized;
}

export default AdvancedWelcomeServiceFactory;
