import type { LoadBalancerStickinessManager } from "@naylence/runtime";
import {
  LOAD_BALANCER_STICKINESS_MANAGER_FACTORY_BASE_TYPE,
  LoadBalancerStickinessManagerFactory,
  type LoadBalancerStickinessManagerConfig,
} from "@naylence/runtime";
import type { KeyProvider } from "@naylence/runtime";

import { AFTLoadBalancerStickinessManager } from "./aft-load-balancer-stickiness-manager.js";
import { createAftVerifier } from "./aft-verifier.js";
import type { AFTVerifier } from "./aft-verifier.js";
import { StickinessMode, normalizeStickinessMode } from "./stickiness-mode.js";

export interface AFTLoadBalancerStickinessManagerConfig
  extends LoadBalancerStickinessManagerConfig {
  type: "AFTLoadBalancerStickinessManager";
  enabled?: boolean;
  clientEcho?: boolean;
  defaultTtlSec?: number;
  cacheMax?: number;
  securityLevel?: StickinessMode;
  maxTtlSec?: number;
}

export const FACTORY_META = {
  base: LOAD_BALANCER_STICKINESS_MANAGER_FACTORY_BASE_TYPE,
  key: "AFTLoadBalancerStickinessManager",
} as const;

const DEFAULT_VALUES = {
  enabled: true,
  clientEcho: false,
  defaultTtlSec: 30,
  cacheMax: 100_000,
  securityLevel: StickinessMode.SIGNED_OPTIONAL,
  maxTtlSec: 7200,
} as const;

function toBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function toNumber(value: unknown, fallback: number): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  return fallback;
}

function normalizeConfig(
  config?:
    | AFTLoadBalancerStickinessManagerConfig
    | Record<string, unknown>
    | null,
): AFTLoadBalancerStickinessManagerConfig {
  const record = (config ?? {}) as Record<string, unknown>;

  const normalizedSecurity = record.securityLevel
    ? normalizeStickinessMode(record.securityLevel as string | StickinessMode)
    : DEFAULT_VALUES.securityLevel;

  return {
    ...record,
    type: "AFTLoadBalancerStickinessManager",
    enabled: toBoolean(record.enabled, DEFAULT_VALUES.enabled),
    clientEcho: toBoolean(record.clientEcho, DEFAULT_VALUES.clientEcho),
    defaultTtlSec: toNumber(record.defaultTtlSec, DEFAULT_VALUES.defaultTtlSec),
    cacheMax: toNumber(record.cacheMax, DEFAULT_VALUES.cacheMax),
    securityLevel: normalizedSecurity,
    maxTtlSec: toNumber(record.maxTtlSec, DEFAULT_VALUES.maxTtlSec),
  } as AFTLoadBalancerStickinessManagerConfig;
}

export class AFTLoadBalancerStickinessManagerFactory extends LoadBalancerStickinessManagerFactory<AFTLoadBalancerStickinessManagerConfig> {
  public readonly type = "AFTLoadBalancerStickinessManager";
  public readonly isDefault = false;

  public async create(
    config?:
      | AFTLoadBalancerStickinessManagerConfig
      | Record<string, unknown>
      | null,
    keyProvider?: KeyProvider | null,
    verifier?: AFTVerifier | null,
  ): Promise<LoadBalancerStickinessManager> {
    const resolvedConfig = normalizeConfig(config);

    let effectiveVerifier = verifier ?? null;
    if (!effectiveVerifier && keyProvider) {
      effectiveVerifier = createAftVerifier({
        securityLevel:
          resolvedConfig.securityLevel ?? DEFAULT_VALUES.securityLevel,
        keyProvider,
        defaultTtlSec:
          resolvedConfig.defaultTtlSec ?? DEFAULT_VALUES.defaultTtlSec,
      });
    }

    if (!effectiveVerifier) {
      throw new Error(
        "AFTLoadBalancerStickinessManagerFactory requires an AFT verifier or key provider",
      );
    }

    return new AFTLoadBalancerStickinessManager(
      resolvedConfig,
      effectiveVerifier,
    );
  }
}

export default AFTLoadBalancerStickinessManagerFactory;
