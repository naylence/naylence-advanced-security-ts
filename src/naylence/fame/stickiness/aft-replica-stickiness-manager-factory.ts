import type { ReplicaStickinessManager } from "@naylence/runtime";
import {
  REPLICA_STICKINESS_MANAGER_FACTORY_BASE_TYPE,
  ReplicaStickinessManagerFactory,
  type ReplicaStickinessManagerConfig,
} from "@naylence/runtime";

import type { AFTHelper } from "./aft-helper.js";
import { AFTReplicaStickinessManager } from "./aft-replica-stickiness-manager.js";
import { StickinessMode, normalizeStickinessMode } from "./stickiness-mode.js";

export interface AFTReplicaStickinessManagerConfig
  extends ReplicaStickinessManagerConfig {
  type: "AFTReplicaStickinessManager";
  securityLevel?: StickinessMode | string;
  maxTtlSec?: number;
}

export interface AFTReplicaStickinessManagerDependencies {
  aftHelper?: AFTHelper | null;
}

export const FACTORY_META = {
  base: REPLICA_STICKINESS_MANAGER_FACTORY_BASE_TYPE,
  key: "AFTReplicaStickinessManager",
} as const;

const DEFAULT_VALUES = {
  securityLevel: StickinessMode.SIGNED_OPTIONAL,
  maxTtlSec: 7200,
} as const;

function normalizeConfig(
  config?: AFTReplicaStickinessManagerConfig | Record<string, unknown> | null,
): AFTReplicaStickinessManagerConfig {
  const record = (config ?? {}) as Record<string, unknown>;

  const normalizedSecurity = record.securityLevel
    ? normalizeStickinessMode(record.securityLevel as string | StickinessMode)
    : DEFAULT_VALUES.securityLevel;

  const securityLevel = normalizedSecurity ?? DEFAULT_VALUES.securityLevel;
  const maxTtlSecValue =
    typeof record.maxTtlSec === "number" && Number.isFinite(record.maxTtlSec)
      ? Math.max(0, Math.floor(record.maxTtlSec))
      : DEFAULT_VALUES.maxTtlSec;

  return {
    ...record,
    type: "AFTReplicaStickinessManager",
    securityLevel,
    maxTtlSec: maxTtlSecValue,
  } as AFTReplicaStickinessManagerConfig;
}

export class AFTReplicaStickinessManagerFactory extends ReplicaStickinessManagerFactory<AFTReplicaStickinessManagerConfig> {
  public readonly type = FACTORY_META.key;
  public readonly isDefault = true;

  public async create(
    config?: AFTReplicaStickinessManagerConfig | Record<string, unknown> | null,
    dependencies?: AFTReplicaStickinessManagerDependencies | null,
  ): Promise<ReplicaStickinessManager> {
    const resolvedConfig = normalizeConfig(config);
    const helper = dependencies?.aftHelper ?? null;
    const securityLevel =
      normalizeStickinessMode(
        resolvedConfig.securityLevel ?? DEFAULT_VALUES.securityLevel,
      ) ?? DEFAULT_VALUES.securityLevel;
    const maxTtlSec =
      typeof resolvedConfig.maxTtlSec === "number" &&
      Number.isFinite(resolvedConfig.maxTtlSec)
        ? Math.max(0, Math.floor(resolvedConfig.maxTtlSec))
        : DEFAULT_VALUES.maxTtlSec;

    return new AFTReplicaStickinessManager({
      securityLevel,
      maxTtlSec,
      aftHelper: helper,
    });
  }
}

export default AFTReplicaStickinessManagerFactory;
