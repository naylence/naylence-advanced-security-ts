import type { NodeWelcomeFrame, SecuritySettings } from "@naylence/core";
import { SigningMaterial } from "@naylence/core";
import {
  AuthInjectionStrategyFactory,
  getLogger,
  SigningConfigClass,
  type AuthInjectionStrategy,
  type AuthInjectionStrategyConfig,
  type SigningConfigOptions,
  type CertificateManager,
  type NodeLike,
  type SigningConfig,
} from "@naylence/runtime";
import {
  CAServiceClient,
  type HttpConnectionGrant,
} from "./ca-service-client.js";
import { CertificateRequestError } from "./ca-types.js";
import { GRANT_PURPOSE_CA_SIGN } from "./grants.js";
import { validateJwkX5cCertificate } from "./util.js";

const logger = getLogger(
  "naylence.fame.security.cert.default_certificate_manager",
);

export type SigningConfigInstance = InstanceType<typeof SigningConfigClass>;

export interface DefaultCertificateManagerOptions {
  readonly signing?:
    | SigningConfigInstance
    | SigningConfigOptions
    | SigningConfig
    | null;
  readonly securitySettings?: SecuritySettings | null;
  readonly caServiceUrl?: string | null;
  readonly cryptoProvider?: unknown | null;
  readonly crypto_provider?: unknown | null;
}

type CertificateMaterial = {
  readonly certificatePem: string;
  readonly certificateChainPem: string | null;
};

const ENV_VAR_FAME_CA_CERTS = "FAME_CA_CERTS";

const CONNECTION_GRANTS_CAMEL = "connectionGrants" as const;
const CONNECTION_GRANTS_SNAKE = "connection_grants" as const;

type CertificateAwareProvider = {
  hasCertificate?: () => boolean;
  nodeCertificatePem?: () => string | null | undefined;
  certificateChainPem?: () => string | null | undefined;
  storeSignedCertificate?: (
    certificatePem: string,
    certificateChainPem?: string | null,
  ) => void;
  setNodeContextFromNodeLike?: (node: NodeLike) => void;
  setNodeContext?: (
    nodeId: string,
    physicalPath: string,
    logicals: string[],
    parentPath?: string | null,
  ) => void;
  prepareForAttach?: (
    nodeId: string,
    physicalPath: string | undefined,
    logicals: string[],
  ) => void;
  createCsr?: (
    nodeId: string,
    physicalPath: string,
    logicals: string[],
    subjectName?: string,
  ) => Promise<string> | string;
  nodeJwk?: () => Record<string, unknown> | null | undefined;
  signatureKeyId?: string | null | undefined;
};

type CaSignGrant = HttpConnectionGrant & {
  auth?: AuthInjectionStrategyConfig | Record<string, unknown> | null;
};

export class DefaultCertificateManager implements CertificateManager {
  public readonly priority = 1500;

  private signing: SigningConfigInstance;
  private securitySettings: SecuritySettings | null;
  private readonly caServiceUrl: string | null;
  private readonly cryptoProviderOverride: unknown | null;
  private node: NodeLike | null = null;
  private pendingWelcomeFrame: NodeWelcomeFrame | null = null;

  public constructor(options: DefaultCertificateManagerOptions = {}) {
    this.signing = normalizeSigningConfig(options.signing ?? null);
    this.securitySettings = options.securitySettings ?? null;
    this.caServiceUrl = options.caServiceUrl ?? null;
    this.cryptoProviderOverride =
      options.cryptoProvider ?? options.crypto_provider ?? null;
  }

  public setSigning(
    signing: SigningConfigInstance | SigningConfigOptions | null,
  ): void {
    this.signing = normalizeSigningConfig(signing);
  }

  public setSecuritySettings(securitySettings: SecuritySettings | null): void {
    this.securitySettings = securitySettings ?? null;
  }

  public async onNodeStarted(node: NodeLike): Promise<void> {
    this.node = node;
    this.prepareProviderContext(node);

    const requiresCertificate = this.requiresCertificates();
    if (requiresCertificate) {
      logger.debug("node_certificate_required_on_start", {
        node_id: node.id,
        physical_path: node.physicalPath,
        has_parent: node.hasParent,
      });

      const fallbackWelcome: NodeWelcomeFrame = {
        security_settings: this.securitySettings ?? undefined,
        system_id: node.id,
        assigned_path: node.physicalPath,
        accepted_logicals: Array.from(node.acceptedLogicals),
      } as unknown as NodeWelcomeFrame;

      const welcomeFrame = this.pendingWelcomeFrame ?? fallbackWelcome;

      const success = await this.ensureCertificate(
        welcomeFrame,
        this.caServiceUrl ? { caServiceUrl: this.caServiceUrl } : undefined,
      );

      if (!success) {
        logger.warning("node_certificate_unavailable_on_start", {
          node_id: node.id,
          physical_path: node.physicalPath,
          message:
            "Certificate provisioning was requested but did not complete",
        });
      }
    } else {
      this.pendingWelcomeFrame = null;
    }
  }

  public async onWelcome(welcomeFrame: NodeWelcomeFrame): Promise<void> {
    const requiresCertificate = this.requiresCertificates(welcomeFrame);
    if (!requiresCertificate) {
      logger.debug("welcome_does_not_require_certificate", {
        system_id: welcomeFrame.systemId ?? null,
      });
      this.pendingWelcomeFrame = null;
      return;
    }

    const success = await this.ensureCertificate(
      welcomeFrame,
      this.caServiceUrl ? { caServiceUrl: this.caServiceUrl } : undefined,
    );

    if (success) {
      return;
    }

    if (!this.node) {
      logger.debug("certificate_provisioning_deferred_until_node_start", {
        system_id: welcomeFrame.systemId ?? null,
        assigned_path: welcomeFrame.assignedPath ?? null,
      });
      return;
    }

    const nodeId = welcomeFrame.systemId ?? "unknown";
    logger.warning("certificate_provisioning_not_completed", {
      node_id: nodeId,
      assigned_path: welcomeFrame.assignedPath ?? null,
      message:
        "Continuing without a provisioned certificate (development mode)",
    });
  }

  public async ensureCertificate(
    welcomeFrame: NodeWelcomeFrame,
    options?: { caServiceUrl?: string | null },
  ): Promise<boolean> {
    const requiresCertificate = this.requiresCertificates(welcomeFrame);
    if (!requiresCertificate) {
      this.pendingWelcomeFrame = null;
      return true;
    }

    this.pendingWelcomeFrame = welcomeFrame;

    const cryptoProvider = this.resolveCryptoProvider();
    if (!cryptoProvider) {
      if (!this.node) {
        logger.debug("crypto_provider_pending_node_start", {
          system_id: welcomeFrame.systemId ?? null,
          assigned_path: welcomeFrame.assignedPath ?? null,
        });
      } else {
        logger.error("crypto_provider_unavailable_for_certificate", {
          system_id: welcomeFrame.systemId ?? null,
          assigned_path: welcomeFrame.assignedPath ?? null,
        });
      }
      return false;
    }

    const nodeId =
      readFrameString(welcomeFrame, "systemId", "system_id") ??
      (typeof cryptoProvider.signatureKeyId === "string"
        ? cryptoProvider.signatureKeyId
        : null);

    if (await this.ensureExistingCertificateIsTrusted(cryptoProvider, nodeId)) {
      this.pendingWelcomeFrame = null;
      return true;
    }

    this.prepareProviderForWelcome(cryptoProvider, welcomeFrame);

    const connectionGrants = readFrameValue<unknown[]>(
      welcomeFrame,
      CONNECTION_GRANTS_CAMEL,
      CONNECTION_GRANTS_SNAKE,
    );
    const caSignGrant = this.getCaSignGrant(connectionGrants);

    if (!caSignGrant) {
      logger.warning("welcome_frame_missing_ca_sign_grant", {
        system_id: nodeId,
        grant_count: Array.isArray(connectionGrants)
          ? connectionGrants.length
          : 0,
      });
    }

    let material: CertificateMaterial | null = null;
    if (caSignGrant) {
      material = await this.requestCertificateFromCa(
        cryptoProvider,
        welcomeFrame,
        caSignGrant,
        options,
      );

      if (!material) {
        logger.warning("ca_certificate_request_failed_falling_back_to_env", {
          system_id: nodeId,
          ca_service_url:
            options?.caServiceUrl ?? this.caServiceUrl ?? caSignGrant.url,
        });
      }
    }

    if (!material) {
      logger.debug("attempting_certificate_resolution_from_environment", {
        system_id: nodeId,
      });
      material = await resolveCertificateMaterial();
    }

    if (!material) {
      logger.warning("certificate_material_not_found", {
        system_id: nodeId,
        assigned_path: readFrameString(
          welcomeFrame,
          "assignedPath",
          "assigned_path",
        ),
        ca_service_url: options?.caServiceUrl ?? this.caServiceUrl,
      });
      return false;
    }

    const stored = storeCertificateMaterial(cryptoProvider, material);
    if (!stored) {
      logger.warning("certificate_storage_not_supported", {
        system_id: nodeId,
      });
      return false;
    }

    const validated = await this.validateProviderCertificate(
      cryptoProvider,
      nodeId,
    );
    if (!validated) {
      return false;
    }

    logger.debug("certificate_material_applied", {
      system_id: nodeId,
      has_chain: Boolean(material.certificateChainPem),
    });
    this.pendingWelcomeFrame = null;
    return true;
  }

  private requiresCertificates(
    welcomeFrame?: NodeWelcomeFrame | null,
  ): boolean {
    const frameMaterial =
      welcomeFrame?.securitySettings?.signing_material ?? null;
    if (frameMaterial === SigningMaterial.X509_CHAIN) {
      return true;
    }

    if (
      this.securitySettings?.signing_material === SigningMaterial.X509_CHAIN
    ) {
      return true;
    }

    if (this.signing.signingMaterial === SigningMaterial.X509_CHAIN) {
      return true;
    }

    return false;
  }

  private prepareProviderContext(node: NodeLike): void {
    const provider = this.resolveCryptoProvider();
    if (!provider) {
      return;
    }

    const awareProvider = provider as CertificateAwareProvider;
    if (typeof awareProvider.setNodeContextFromNodeLike === "function") {
      awareProvider.setNodeContextFromNodeLike(node);
      return;
    }

    if (typeof awareProvider.setNodeContext === "function") {
      awareProvider.setNodeContext(
        node.id,
        node.physicalPath,
        Array.from(node.acceptedLogicals),
        null,
      );
    }
  }

  private prepareProviderForWelcome(
    provider: CertificateAwareProvider,
    welcomeFrame: NodeWelcomeFrame,
  ): void {
    const logicals = Array.isArray(welcomeFrame.acceptedLogicals)
      ? welcomeFrame.acceptedLogicals.filter(
          (value: unknown): value is string => typeof value === "string",
        )
      : [];

    if (
      typeof provider.prepareForAttach === "function" &&
      typeof welcomeFrame.systemId === "string"
    ) {
      provider.prepareForAttach(
        welcomeFrame.systemId,
        typeof welcomeFrame.assignedPath === "string"
          ? welcomeFrame.assignedPath
          : undefined,
        logicals,
      );
    }
  }

  private resolveCryptoProvider(): CertificateAwareProvider | null {
    // First check if we have a crypto provider override
    if (this.cryptoProviderOverride) {
      return this.cryptoProviderOverride as CertificateAwareProvider;
    }

    // Otherwise, try to get from the node
    const candidate = this.node?.cryptoProvider ?? null;
    if (!candidate) {
      return null;
    }
    return candidate as CertificateAwareProvider;
  }

  private async ensureExistingCertificateIsTrusted(
    provider: CertificateAwareProvider,
    nodeId: string | null,
  ): Promise<boolean> {
    if (!providerHasCertificate(provider)) {
      return false;
    }

    const validated = await this.validateProviderCertificate(provider, nodeId);
    if (!validated) {
      logger.error("existing_certificate_validation_failed", {
        node_id: nodeId,
      });
      return false;
    }

    logger.debug("existing_certificate_validated", {
      node_id: nodeId,
    });
    return true;
  }

  private getCaSignGrant(
    connectionGrants?: unknown[] | null,
  ): CaSignGrant | null {
    if (!Array.isArray(connectionGrants)) {
      return null;
    }

    for (const candidate of connectionGrants) {
      if (!candidate || typeof candidate !== "object") {
        continue;
      }

      const grantRecord = candidate as Record<string, unknown>;
      const purpose = readRecordString(grantRecord, "purpose");
      if (purpose !== GRANT_PURPOSE_CA_SIGN) {
        continue;
      }

      const url = readRecordString(grantRecord, "url", "baseUrl", "base_url");
      if (!url) {
        logger.warning("ca_sign_grant_missing_url", {
          grant_keys: Object.keys(grantRecord),
        });
        continue;
      }

      const authConfig = readGrantAuthConfig(grantRecord);
      return {
        url,
        ...(authConfig ? { auth: authConfig } : {}),
      };
    }

    return null;
  }

  private async requestCertificateFromCa(
    provider: CertificateAwareProvider,
    welcomeFrame: NodeWelcomeFrame,
    grant: CaSignGrant,
    options?: { caServiceUrl?: string | null },
  ): Promise<CertificateMaterial | null> {
    const nodeId =
      readFrameString(welcomeFrame, "systemId", "system_id") ??
      (typeof provider.signatureKeyId === "string"
        ? provider.signatureKeyId
        : null);

    if (!nodeId) {
      logger.warning("certificate_request_missing_node_id");
      return null;
    }

    const physicalPath = readFrameString(
      welcomeFrame,
      "assignedPath",
      "assigned_path",
    );
    if (!physicalPath) {
      logger.warning("certificate_request_missing_physical_path", {
        node_id: nodeId,
      });
      return null;
    }

    const logicals = Array.isArray(welcomeFrame.acceptedLogicals)
      ? welcomeFrame.acceptedLogicals.filter(
          (value): value is string => typeof value === "string",
        )
      : [];

    if (typeof provider.createCsr !== "function") {
      logger.warning("crypto_provider_missing_create_csr", {
        node_id: nodeId,
      });
      return null;
    }

    let csrPem: string;
    try {
      const result = provider.createCsr(nodeId, physicalPath, logicals);
      csrPem = typeof result === "string" ? result : await result;
    } catch (error) {
      logger.error("csr_generation_failed", {
        node_id: nodeId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }

    const caServiceUrl =
      options?.caServiceUrl ?? this.caServiceUrl ?? grant.url;
    if (!caServiceUrl) {
      logger.error("ca_service_url_unavailable", {
        node_id: nodeId,
      });
      return null;
    }

    const connectionGrant: HttpConnectionGrant = {
      url: caServiceUrl,
    };

    let authStrategy: AuthInjectionStrategy | null = null;
    try {
      authStrategy = await this.createAuthStrategyForGrant(grant);
    } catch (error) {
      logger.error("ca_sign_auth_strategy_creation_failed", {
        node_id: nodeId,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }

    const client = new CAServiceClient(connectionGrant);

    try {
      if (authStrategy) {
        await authStrategy.apply(client);
      }

      const [certificatePem, certificateChainPem] =
        await client.requestCertificate(csrPem, nodeId, physicalPath, logicals);

      logger.debug("certificate_received_from_ca_service", {
        node_id: nodeId,
        has_chain: Boolean(certificateChainPem),
        ca_service_url: caServiceUrl,
      });

      return {
        certificatePem,
        certificateChainPem: certificateChainPem ?? null,
      };
    } catch (error) {
      if (error instanceof CertificateRequestError) {
        logger.error("certificate_request_failed", {
          node_id: nodeId,
          error: error.message,
        });
      } else {
        logger.error("certificate_request_unhandled_error", {
          node_id: nodeId,
          error: error instanceof Error ? error.message : String(error),
        });
      }
      return null;
    } finally {
      if (authStrategy) {
        try {
          await authStrategy.cleanup();
        } catch (cleanupError) {
          logger.debug("auth_strategy_cleanup_failed", {
            error:
              cleanupError instanceof Error
                ? cleanupError.message
                : String(cleanupError),
          });
        }
      }
    }
  }

  private async createAuthStrategyForGrant(
    grant: CaSignGrant,
  ): Promise<AuthInjectionStrategy | null> {
    const authConfig = grant.auth ?? null;
    if (!authConfig) {
      return null;
    }

    const normalizedConfig = normalizeAuthConfig(authConfig);
    if (!normalizedConfig) {
      return null;
    }

    return AuthInjectionStrategyFactory.createAuthInjectionStrategy(
      normalizedConfig,
    );
  }

  private async validateProviderCertificate(
    provider: CertificateAwareProvider,
    nodeId: string | null,
  ): Promise<boolean> {
    const trustStorePem = await resolveTrustStorePem();
    if (!trustStorePem) {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: `${ENV_VAR_FAME_CA_CERTS}_not_set`,
      });
      return false;
    }

    if (typeof provider.nodeJwk !== "function") {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: "crypto_provider_lacks_node_jwk",
      });
      return false;
    }

    let jwk: Record<string, unknown> | null;
    try {
      jwk = provider.nodeJwk() ?? null;
    } catch (error) {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: "node_jwk_retrieval_failed",
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }

    if (!jwk) {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: "node_jwk_missing",
      });
      return false;
    }

    const x5c = (jwk as { x5c?: unknown }).x5c;
    if (
      !Array.isArray(x5c) ||
      x5c.length === 0 ||
      x5c.some((entry) => typeof entry !== "string")
    ) {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: "invalid_certificate_chain",
      });
      return false;
    }

    try {
      const result = validateJwkX5cCertificate({
        jwk,
        trustStorePem,
        enforceNameConstraints: true,
        strict: false,
      });

      if (!result.isValid) {
        logger.error("trust_anchor_validation_failed", {
          node_id: nodeId,
          reason: result.error ?? "validation_failed",
        });
        return false;
      }

      logger.debug("certificate_chain_validation_successful", {
        node_id: nodeId,
      });
      return true;
    } catch (error) {
      logger.error("trust_anchor_validation_failed", {
        node_id: nodeId,
        reason: "validation_error",
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }
}

function normalizeSigningConfig(
  value: SigningConfigInstance | SigningConfigOptions | SigningConfig | null,
): SigningConfigInstance {
  if (value instanceof SigningConfigClass) {
    return value;
  }

  if (value && typeof value === "object") {
    return new SigningConfigClass(value);
  }

  return new SigningConfigClass();
}

async function resolveCertificateMaterial(): Promise<CertificateMaterial | null> {
  const certificatePem = await resolvePemFromEnvironment(
    "FAME_NODE_CERT_PEM",
    "FAME_NODE_CERT_FILE",
  );
  if (!certificatePem) {
    return null;
  }

  const certificateChainPem = await resolvePemFromEnvironment(
    "FAME_NODE_CERT_CHAIN_PEM",
    "FAME_NODE_CERT_CHAIN_FILE",
  );

  return {
    certificatePem,
    certificateChainPem,
  };
}

async function resolvePemFromEnvironment(
  envVar: string,
  fileVar: string,
): Promise<string | null> {
  if (!hasProcessEnv()) {
    return null;
  }

  const inlineValue = process.env?.[envVar];
  if (inlineValue && inlineValue.trim().length > 0) {
    return normalizePem(inlineValue);
  }

  const filePath = process.env?.[fileVar];
  if (!filePath || filePath.trim().length === 0) {
    return null;
  }

  if (!isNodeProcess()) {
    logger.debug("pem_file_unavailable_in_browser", {
      env_var: fileVar,
    });
    return null;
  }

  try {
    const fs = await import("node:fs/promises");
    const content = await fs.readFile(filePath, "utf8");
    return normalizePem(content);
  } catch (error) {
    logger.warning("failed_to_read_certificate_file", {
      file: filePath,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

function normalizePem(value: string): string {
  return value.replace(/\r/g, "").trim();
}

function hasProcessEnv(): boolean {
  return typeof process !== "undefined" && !!process?.env;
}

function isNodeProcess(): boolean {
  return (
    typeof process !== "undefined" &&
    typeof process.versions === "object" &&
    typeof process.versions?.node === "string"
  );
}

function providerHasCertificate(provider: CertificateAwareProvider): boolean {
  if (typeof provider.hasCertificate === "function") {
    try {
      return Boolean(provider.hasCertificate());
    } catch (error) {
      logger.debug("has_certificate_check_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (typeof provider.nodeCertificatePem === "function") {
    try {
      return Boolean(provider.nodeCertificatePem());
    } catch (error) {
      logger.debug("node_certificate_check_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  return false;
}

function storeCertificateMaterial(
  provider: CertificateAwareProvider,
  material: CertificateMaterial,
): boolean {
  if (typeof provider.storeSignedCertificate !== "function") {
    return false;
  }

  try {
    provider.storeSignedCertificate(
      material.certificatePem,
      material.certificateChainPem,
    );
    return true;
  } catch (error) {
    logger.warning("failed_to_store_certificate", {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

function readFrameValue<T = unknown>(
  frame: NodeWelcomeFrame,
  ...keys: string[]
): T | null {
  const record = frame as Record<string, unknown>;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) {
      const value = record[key];
      if (value !== undefined && value !== null) {
        return value as T;
      }
    }
  }
  return null;
}

function readFrameString(
  frame: NodeWelcomeFrame,
  ...keys: string[]
): string | null {
  const value = readFrameValue<unknown>(frame, ...keys);
  if (typeof value === "string" && value.length > 0) {
    return value;
  }
  return null;
}

function readRecordString(
  source: Record<string, unknown>,
  ...keys: string[]
): string | null {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return null;
}

function readGrantAuthConfig(
  source: Record<string, unknown>,
): AuthInjectionStrategyConfig | Record<string, unknown> | null {
  const candidate =
    source.auth ??
    source.authConfig ??
    source.auth_config ??
    source.authentication ??
    source.authenticationConfig ??
    source.authentication_config ??
    null;

  if (!candidate || typeof candidate !== "object") {
    return null;
  }

  return candidate as Record<string, unknown>;
}

function normalizeAuthConfig(
  candidate: AuthInjectionStrategyConfig | Record<string, unknown>,
): AuthInjectionStrategyConfig | null {
  if (!candidate || typeof candidate !== "object") {
    return null;
  }

  const normalized = candidate as AuthInjectionStrategyConfig;
  if (!normalized.type || typeof normalized.type !== "string") {
    logger.warning("auth_strategy_missing_type", {
      provided_keys: Object.keys(candidate as Record<string, unknown>),
    });
    return null;
  }

  return normalized;
}

async function resolveTrustStorePem(): Promise<string | null> {
  if (!hasProcessEnv()) {
    return null;
  }

  const rawValue = process.env?.[ENV_VAR_FAME_CA_CERTS];
  if (!rawValue || rawValue.trim().length === 0) {
    return null;
  }

  if (rawValue.trim().startsWith("-----BEGIN")) {
    return rawValue.replace(/\r/g, "").trim();
  }

  if (!isNodeProcess()) {
    logger.debug("trust_store_file_unavailable_in_browser", {
      env_var: ENV_VAR_FAME_CA_CERTS,
    });
    return null;
  }

  const filePath = rawValue.trim();
  try {
    const fs = await import("node:fs/promises");
    const content = await fs.readFile(filePath, "utf8");
    return content.replace(/\r/g, "").trim();
  } catch (error) {
    logger.error("failed_to_read_trust_store", {
      file: filePath,
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}

export default DefaultCertificateManager;
