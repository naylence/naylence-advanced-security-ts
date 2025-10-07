import {
  ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  EncryptionManagerFactory,
  type EncryptionManagerConfig,
  type EncryptionFactoryDependencies,
} from "naylence-runtime";
import type {
  EncryptionManager,
  EncryptionOptions,
} from "naylence-runtime";
import type { KeyProvider } from "naylence-runtime";
import type { CryptoProvider } from "naylence-runtime";
import type { NodeLike } from "naylence-runtime";
import { X25519EncryptionManager } from "./x25519-encryption-manager.js";

export interface X25519EncryptionManagerConfig extends EncryptionManagerConfig {
  readonly type: "X25519EncryptionManager";
  readonly priority: number;
  readonly supportedAlgorithms: readonly string[];
  readonly encryptionType: string;
}

const DEFAULT_SUPPORTED_ALGORITHMS = [
  "X25519",
  "ECDH-ES+A256GCM",
  "chacha20-poly1305",
  "aes-256-gcm",
] as const;

export const FACTORY_META = {
  base: ENCRYPTION_MANAGER_FACTORY_BASE_TYPE,
  key: "X25519EncryptionManager",
} as const;

export class X25519EncryptionManagerFactory extends EncryptionManagerFactory<X25519EncryptionManagerConfig> {
  public readonly type = FACTORY_META.key;
  public readonly priority: number;

  private readonly supportedAlgorithms: readonly string[];
  private readonly encryptionType: string;

  constructor(config?: Partial<X25519EncryptionManagerConfig> | null) {
    super();
    this.supportedAlgorithms = config?.supportedAlgorithms ?? DEFAULT_SUPPORTED_ALGORITHMS;
    this.encryptionType = config?.encryptionType ?? "sealed";
    this.priority = config?.priority ?? 100;
  }

  public getSupportedAlgorithms(): readonly string[] {
    return this.supportedAlgorithms;
  }

  public getEncryptionType(): string {
    return this.encryptionType;
  }

  public supportsOptions(opts?: EncryptionOptions | null): boolean {
    if (!opts) {
      return false;
    }

    return Boolean(
      opts.recipPub ||
        opts.recipientPublicKey ||
        opts.recip_pub ||
        opts.recipKid ||
        opts.recip_kid ||
        opts.recipientKeyId ||
        opts.requestAddress
    );
  }

  public async create(
  _config?: X25519EncryptionManagerConfig | Record<string, unknown> | null,
    ...factoryArgs: unknown[]
  ): Promise<EncryptionManager> {
    const [dependencies] = factoryArgs as [EncryptionFactoryDependencies | undefined];
    const keyProvider = this.resolveKeyProvider(dependencies);
    const cryptoProvider = this.resolveCryptoProvider(dependencies);
    const nodeLike = this.resolveNodeLike(dependencies);

    if (!keyProvider) {
      throw new Error("X25519EncryptionManager requires a keyProvider dependency");
    }

    return new X25519EncryptionManager({
      keyProvider,
      cryptoProvider,
      nodeLike,
    });
  }

  private resolveKeyProvider(dependencies?: EncryptionFactoryDependencies): KeyProvider | null {
    if (!dependencies) {
      return null;
    }
    return (
      (dependencies.keyProvider as KeyProvider | undefined) ??
      (dependencies["key_provider"] as KeyProvider | undefined) ??
      null
    );
  }

  private resolveCryptoProvider(dependencies?: EncryptionFactoryDependencies): CryptoProvider | null {
    if (!dependencies) {
      return null;
    }
    return (
      (dependencies.cryptoProvider as CryptoProvider | undefined) ??
      (dependencies["crypto_provider"] as CryptoProvider | undefined) ??
      (dependencies["crypto"] as CryptoProvider | undefined) ??
      null
    );
  }

  private resolveNodeLike(dependencies?: EncryptionFactoryDependencies): NodeLike | null {
    if (!dependencies) {
      return null;
    }

    const nodeCandidate =
      (dependencies.nodeLike as NodeLike | undefined) ??
      (dependencies["nodeLike"] as NodeLike | undefined) ??
      (dependencies["node_like"] as NodeLike | undefined);
    return nodeCandidate ?? null;
  }
}

export default X25519EncryptionManagerFactory;
