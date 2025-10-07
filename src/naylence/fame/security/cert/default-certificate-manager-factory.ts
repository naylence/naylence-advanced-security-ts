import type { SecuritySettings } from "naylence-core";
import { SigningConfigClass } from "naylence-runtime";
import {
  CertificateManagerFactory,
  CERTIFICATE_MANAGER_FACTORY_BASE_TYPE,
  type CertificateManagerConfig,
} from "naylence-runtime";

import {
  DefaultCertificateManager,
  type DefaultCertificateManagerOptions,
  type SigningConfigInstance,
} from "./default-certificate-manager.js";
import type { SigningConfig } from "naylence-runtime";
import type { CertificateManager } from "naylence-runtime";

export interface DefaultCertificateManagerConfig extends CertificateManagerConfig {
  type: "DefaultCertificateManager";
  caServiceUrl?: string | null;
  ca_service_url?: string | null;
  securitySettings?: SecuritySettings | null;
  security_settings?: SecuritySettings | null;
  cryptoProvider?: unknown | null;
  crypto_provider?: unknown | null;
}

export const FACTORY_META = {
  base: CERTIFICATE_MANAGER_FACTORY_BASE_TYPE,
  key: "DefaultCertificateManager",
} as const;

function normalizeConfig(
  config?: DefaultCertificateManagerConfig | Record<string, unknown> | null
): DefaultCertificateManagerConfig {
  if (!config) {
    return { type: "DefaultCertificateManager" };
  }

  const { type: _ignoredType, ...rest } = config as Record<string, unknown>;
  const normalized = {
    ...rest,
    type: "DefaultCertificateManager",
  } as DefaultCertificateManagerConfig;
  return normalized;
}

function normalizeSecuritySettings(
  config: DefaultCertificateManagerConfig,
  explicit?: SecuritySettings | null
): SecuritySettings | null {
  if (explicit) {
    return explicit;
  }

  if (config.securitySettings) {
    return config.securitySettings;
  }

  if (config.security_settings) {
    return config.security_settings;
  }

  return null;
}

function normalizeSigning(
  config: DefaultCertificateManagerConfig,
  explicit?: SigningConfig | null
): SigningConfigInstance | null {
  if (explicit instanceof SigningConfigClass) {
    return explicit;
  }

  if (explicit && typeof explicit === "object") {
    return new SigningConfigClass(explicit);
  }

  const candidate = (config as { signing?: unknown }).signing ?? null;
  if (candidate instanceof SigningConfigClass) {
    return candidate;
  }

  if (candidate && typeof candidate === "object") {
    return new SigningConfigClass(candidate);
  }

  return null;
}

function normalizeOptions(
  config: DefaultCertificateManagerConfig,
  securitySettings: SecuritySettings | null,
  signing: SigningConfigInstance | null
): DefaultCertificateManagerOptions {
  const caServiceUrl = config.caServiceUrl ?? config.ca_service_url ?? null;
  const cryptoProvider = config.cryptoProvider ?? config.crypto_provider ?? null;

  return {
    securitySettings,
    signing,
    caServiceUrl,
    cryptoProvider,
  };
}

export class DefaultCertificateManagerFactory extends CertificateManagerFactory<DefaultCertificateManagerConfig> {
  public readonly type = "DefaultCertificateManager";
  public readonly isDefault = true;
  public readonly priority = 100;

  public async create(
    config?: DefaultCertificateManagerConfig | Record<string, unknown> | null,
    securitySettings?: SecuritySettings | null,
    signing?: SigningConfig | null,
    ..._factoryArgs: unknown[]
  ): Promise<CertificateManager> {
    const normalizedConfig = normalizeConfig(config);
    const resolvedSecuritySettings = normalizeSecuritySettings(normalizedConfig, securitySettings ?? null);
    const resolvedSigning = normalizeSigning(normalizedConfig, signing ?? null);
    const options = normalizeOptions(normalizedConfig, resolvedSecuritySettings, resolvedSigning);

    return new DefaultCertificateManager(options);
  }
}

export default DefaultCertificateManagerFactory;
