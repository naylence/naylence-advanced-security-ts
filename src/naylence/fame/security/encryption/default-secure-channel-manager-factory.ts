import {
  SECURE_CHANNEL_MANAGER_FACTORY_BASE_TYPE,
  SecureChannelManagerFactory,
  type SecureChannelManagerConfig,
} from "naylence-runtime";
import type { SecureChannelManager } from "naylence-runtime";
import { DefaultSecureChannelManager } from "./default-secure-channel-manager.js";

export interface DefaultSecureChannelManagerConfig extends SecureChannelManagerConfig {
  readonly type: "DefaultSecureChannelManager";
  readonly channelTtlSeconds?: number;
  readonly channelTtl?: number;
  readonly channel_ttl?: number;
}

export const FACTORY_META = {
  base: SECURE_CHANNEL_MANAGER_FACTORY_BASE_TYPE,
  key: "DefaultSecureChannelManager",
} as const;

export class DefaultSecureChannelManagerFactory extends SecureChannelManagerFactory<DefaultSecureChannelManagerConfig> {
  public readonly type = "DefaultSecureChannelManager";
  public readonly isDefault = true;
  public readonly priority = 500;

  public async create(
    config: DefaultSecureChannelManagerConfig | Record<string, unknown> | null = null
  ): Promise<SecureChannelManager> {
    const ttl = this.resolveChannelTtl(config);
    return new DefaultSecureChannelManager(ttl ? { channelTtlSeconds: ttl } : {});
  }

  public getSupportedAlgorithms(): readonly string[] {
    return ["CHACHA20P1305"];
  }

  private resolveChannelTtl(
    config: DefaultSecureChannelManagerConfig | Record<string, unknown> | null
  ): number | undefined {
    if (!config) {
      return undefined;
    }

    const candidates: unknown[] = [
      (config as DefaultSecureChannelManagerConfig).channelTtlSeconds,
      (config as DefaultSecureChannelManagerConfig).channelTtl,
      (config as DefaultSecureChannelManagerConfig).channel_ttl,
      (config as Record<string, unknown>).channelTTL,
    ];

    for (const candidate of candidates) {
      const normalized = this.toPositiveNumber(candidate);
      if (typeof normalized === "number") {
        return normalized;
      }
    }

    return undefined;
  }

  private toPositiveNumber(value: unknown): number | undefined {
    if (typeof value === "number" && Number.isFinite(value) && value > 0) {
      return value;
    }

    if (typeof value === "string" && value.trim() !== "") {
      const parsed = Number(value);
      if (Number.isFinite(parsed) && parsed > 0) {
        return parsed;
      }
    }

    return undefined;
  }
}

export default DefaultSecureChannelManagerFactory;
