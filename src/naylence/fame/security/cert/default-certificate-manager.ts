import type { NodeWelcomeFrame, SecuritySettings } from "naylence-core";
import { SigningMaterial } from "naylence-core";
import { getLogger, SigningConfigClass, type SigningConfigOptions } from "naylence-runtime";
import type { CertificateManager } from "naylence-runtime";
import type { NodeLike } from "naylence-runtime";
import type { SigningConfig } from "naylence-runtime";

const logger = getLogger("naylence.advanced.security.cert.default-manager");

export type SigningConfigInstance = InstanceType<typeof SigningConfigClass>;

export interface DefaultCertificateManagerOptions {
  readonly signing?: SigningConfigInstance | SigningConfigOptions | SigningConfig | null;
  readonly securitySettings?: SecuritySettings | null;
  readonly caServiceUrl?: string | null;
  readonly cryptoProvider?: unknown | null;
  readonly crypto_provider?: unknown | null;
}

type CertificateMaterial = {
  readonly certificatePem: string;
  readonly certificateChainPem: string | null;
};

type CertificateAwareProvider = {
  hasCertificate?: () => boolean;
  nodeCertificatePem?: () => string | null | undefined;
  certificateChainPem?: () => string | null | undefined;
  storeSignedCertificate?: (certificatePem: string, certificateChainPem?: string | null) => void;
  setNodeContextFromNodeLike?: (node: NodeLike) => void;
  setNodeContext?: (
    nodeId: string,
    physicalPath: string,
    logicals: string[],
    parentPath?: string | null
  ) => void;
  prepareForAttach?: (nodeId: string, physicalPath: string | undefined, logicals: string[]) => void;
};

export class DefaultCertificateManager implements CertificateManager {
  public readonly priority = 1500;

  private signing: SigningConfigInstance;
  private securitySettings: SecuritySettings | null;
  private readonly caServiceUrl: string | null;
  private readonly cryptoProviderOverride: unknown | null;
  private node: NodeLike | null = null;

  public constructor(options: DefaultCertificateManagerOptions = {}) {
    this.signing = normalizeSigningConfig(options.signing ?? null);
    this.securitySettings = options.securitySettings ?? null;
    this.caServiceUrl = options.caServiceUrl ?? null;
    this.cryptoProviderOverride = options.cryptoProvider ?? options.crypto_provider ?? null;
  }

  public setSigning(signing: SigningConfigInstance | SigningConfigOptions | null): void {
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

      const welcomeLike: NodeWelcomeFrame = {
        security_settings: this.securitySettings ?? undefined,
        system_id: node.id,
        assigned_path: node.physicalPath,
        accepted_logicals: Array.from(node.acceptedLogicals),
      } as unknown as NodeWelcomeFrame;

      const success = await this.ensureCertificate(
        welcomeLike,
        this.caServiceUrl ? { caServiceUrl: this.caServiceUrl } : undefined
      );

      if (!success) {
        logger.warning("node_certificate_unavailable_on_start", {
          node_id: node.id,
          physical_path: node.physicalPath,
          message: "Certificate provisioning was requested but did not complete",
        });
      }
    }
  }

  public async onWelcome(welcomeFrame: NodeWelcomeFrame): Promise<void> {
    const requiresCertificate = this.requiresCertificates(welcomeFrame);
    if (!requiresCertificate) {
      logger.debug("welcome_does_not_require_certificate", {
        system_id: welcomeFrame.systemId ?? null,
      });
      return;
    }

    const success = await this.ensureCertificate(
      welcomeFrame,
      this.caServiceUrl ? { caServiceUrl: this.caServiceUrl } : undefined
    );

    if (!success) {
      const nodeId = welcomeFrame.systemId ?? "unknown";
      logger.warning("certificate_provisioning_not_completed", {
        node_id: nodeId,
        assigned_path: welcomeFrame.assignedPath ?? null,
        message: "Continuing without a provisioned certificate (development mode)",
      });
    }
  }

  public async ensureCertificate(
    welcomeFrame: NodeWelcomeFrame,
    options?: { caServiceUrl?: string | null }
  ): Promise<boolean> {
    const requiresCertificate = this.requiresCertificates(welcomeFrame);
    if (!requiresCertificate) {
      return true;
    }

    const cryptoProvider = this.resolveCryptoProvider();
    if (!cryptoProvider) {
      logger.error("crypto_provider_unavailable_for_certificate", {
        system_id: welcomeFrame.systemId ?? null,
        assigned_path: welcomeFrame.assignedPath ?? null,
      });
      return false;
    }

    if (providerHasCertificate(cryptoProvider)) {
      logger.debug("certificate_already_present", {
        system_id: welcomeFrame.systemId ?? null,
      });
      return true;
    }

    this.prepareProviderForWelcome(cryptoProvider, welcomeFrame);

    const material = await resolveCertificateMaterial();
    if (!material) {
      logger.warning("certificate_material_not_found", {
        system_id: welcomeFrame.systemId ?? null,
        assigned_path: welcomeFrame.assignedPath ?? null,
        ca_service_url: options?.caServiceUrl ?? this.caServiceUrl,
      });
      return true;
    }

    const stored = storeCertificateMaterial(cryptoProvider, material);
    if (!stored) {
      logger.warning("certificate_storage_not_supported", {
        system_id: welcomeFrame.systemId ?? null,
      });
      return true;
    }

    logger.debug("certificate_material_applied", {
      system_id: welcomeFrame.systemId ?? null,
      has_chain: material.certificateChainPem ? true : false,
    });
    return true;
  }

  private requiresCertificates(welcomeFrame?: NodeWelcomeFrame | null): boolean {
    const frameMaterial = welcomeFrame?.securitySettings?.signing_material ?? null;
    if (frameMaterial === SigningMaterial.X509_CHAIN) {
      return true;
    }

    if (this.securitySettings?.signing_material === SigningMaterial.X509_CHAIN) {
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
        null
      );
    }
  }

  private prepareProviderForWelcome(
    provider: CertificateAwareProvider,
    welcomeFrame: NodeWelcomeFrame
  ): void {
    const logicals = Array.isArray(welcomeFrame.acceptedLogicals)
      ? welcomeFrame.acceptedLogicals.filter((value: unknown): value is string => typeof value === "string")
      : [];

    if (
      typeof provider.prepareForAttach === "function" &&
      typeof welcomeFrame.systemId === "string"
    ) {
      provider.prepareForAttach(
        welcomeFrame.systemId,
        typeof welcomeFrame.assignedPath === "string" ? welcomeFrame.assignedPath : undefined,
        logicals
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
}

function normalizeSigningConfig(
  value: SigningConfigInstance | SigningConfigOptions | SigningConfig | null
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
  const certificatePem = await resolvePemFromEnvironment("FAME_NODE_CERT_PEM", "FAME_NODE_CERT_FILE");
  if (!certificatePem) {
    return null;
  }

  const certificateChainPem = await resolvePemFromEnvironment(
    "FAME_NODE_CERT_CHAIN_PEM",
    "FAME_NODE_CERT_CHAIN_FILE"
  );

  return {
    certificatePem,
    certificateChainPem,
  };
}

async function resolvePemFromEnvironment(envVar: string, fileVar: string): Promise<string | null> {
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
  material: CertificateMaterial
): boolean {
  if (typeof provider.storeSignedCertificate !== "function") {
    return false;
  }

  try {
    provider.storeSignedCertificate(material.certificatePem, material.certificateChainPem);
    return true;
  } catch (error) {
    logger.warning("failed_to_store_certificate", {
      error: error instanceof Error ? error.message : String(error),
    });
    return false;
  }
}

export default DefaultCertificateManager;
