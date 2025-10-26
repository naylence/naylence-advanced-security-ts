import {
  DeliveryOriginType,
  NodeLike,
  KeyManager,
  KeyStore,
  KeyRecord,
  DefaultKeyManager,
  getKeyStore,
  getLogger,
  currentTraceId,
  validateJwkComplete,
  JWKValidationError,
  JsonWebKey,
  TaskSpawner,
  SpawnedTask,
} from "@naylence/runtime";

import {
  validateJwkX5cCertificate,
  type ValidateJwkX5cCertificateResult,
} from "../cert/util.js";

const logger = getLogger("naylence.fame.security.keys.x5c_key_manager");

interface X509Module {
  X509Certificate: new (rawData: Uint8Array) => {
    readonly notAfter: Date;
  };
}

let x509ModulePromise: Promise<X509Module | null> | null = null;

async function loadX509Module(): Promise<X509Module | null> {
  if (!x509ModulePromise) {
    x509ModulePromise = import("@peculiar/x509")
      .then((mod) => {
        if (mod && typeof mod.X509Certificate === "function") {
          return { X509Certificate: mod.X509Certificate };
        }
        return null;
      })
      .catch((error) => {
        logger.warning("certificate_module_unavailable", {
          error: error instanceof Error ? error.message : String(error),
        });
        return null;
      });
  }

  return x509ModulePromise;
}

function decodeBase64Cert(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value, "base64");
  }

  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export interface X5CKeyManagerOptions {
  readonly keyStore?: KeyStore | null;
  readonly certPurgeIntervalSeconds?: number;
}

export class X5CKeyManager extends TaskSpawner implements KeyManager {
  public readonly priority = 1000;

  private readonly keyStore: KeyStore;
  private readonly inner: DefaultKeyManager;
  private readonly certPurgeInterval: number;
  private purgeTask: SpawnedTask<void> | null = null;

  constructor({
    keyStore = null,
    certPurgeIntervalSeconds = 3600,
  }: X5CKeyManagerOptions = {}) {
    super();
    this.keyStore = keyStore ?? getKeyStore();
    this.inner = new DefaultKeyManager({ keyStore: this.keyStore });
    this.certPurgeInterval = certPurgeIntervalSeconds;
  }

  public async onNodeStarted(node: NodeLike): Promise<void> {
    await this.inner.onNodeStarted(node);
    this.startPurgeLoop();

    logger.debug("x5c_key_manager_started", {
      cert_purge_interval: this.certPurgeInterval,
    });
  }

  public async onNodeStopped(node: NodeLike): Promise<void> {
    logger.debug("x5c_key_manager_stopping");
    await this.shutdownTasks({ gracePeriod: 500, joinTimeout: 500 });
    this.purgeTask = null;
    await this.inner.onNodeStopped(node);
    logger.debug("x5c_key_manager_stopped");
  }

  public async getKey(kid: string): Promise<KeyRecord> {
    return this.inner.getKey(kid);
  }

  public async hasKey(kid: string): Promise<boolean> {
    return this.inner.hasKey(kid);
  }

  public async addKeys(options: {
    keys: Array<Record<string, unknown>>;
    sid?: string;
    physicalPath: string;
    systemId: string;
    origin: DeliveryOriginType;
    skipSidValidation?: boolean;
  }): Promise<void> {
    const {
      keys,
      sid,
      physicalPath,
      systemId,
      origin,
      skipSidValidation = false,
    } = options;

    const trustStore = resolveTrustStorePath();
    const enforceNameConstraints = true;

    const validKeys: Array<Record<string, unknown>> = [];
    let rejectedCount = 0;

    for (const key of keys) {
      try {
        validateJwkComplete(key as JsonWebKey);

        if (Array.isArray((key as Record<string, unknown>).x5c) && trustStore) {
          const validationResult = validateJwkX5cCertificateWrapper({
            jwk: key as Record<string, unknown>,
            trustStore,
            enforceNameConstraints,
            origin,
            systemId,
            physicalPath,
          });

          if (!validationResult.accepted) {
            rejectedCount += 1;
            if (validationResult.skip) {
              continue;
            }
          }
        }

        validKeys.push(key);
      } catch (error) {
        if (error instanceof JWKValidationError) {
          logger.warning("rejected_invalid_jwk_in_announce", {
            kid: typeof key?.kid === "string" ? key.kid : "unknown",
            from_system_id: systemId,
            from_physical_path: physicalPath,
            error: error.message,
          });
          rejectedCount += 1;
          continue;
        }
        throw error;
      }
    }

    if (validKeys.length === 0) {
      logger.warning("no_valid_keys_in_announce", {
        from_system_id: systemId,
        from_physical_path: physicalPath,
        total_keys: keys.length,
        rejected_count: rejectedCount,
      });
      return;
    }

    logger.debug("adding_keys", {
      key_ids: validKeys.map((key) =>
        typeof key?.kid === "string" ? key.kid : "unknown",
      ),
      source_system_id: systemId,
      from_physical_path: physicalPath,
      trace_id: currentTraceId(),
      origin,
      valid_count: validKeys.length,
      rejected_count: rejectedCount,
    });

    const hasEncryptionKeys = validKeys.some(
      (key) => typeof key?.use === "string" && key.use === "enc",
    );

    if (hasEncryptionKeys) {
      logger.debug("checking_for_old_encryption_keys_to_remove", {
        physical_path: physicalPath,
        origin,
        new_enc_keys: validKeys
          .filter((key) => typeof key?.use === "string" && key.use === "enc")
          .map((key) => (typeof key?.kid === "string" ? key.kid : "unknown")),
      });

      try {
        const grouped = await this.keyStore.getKeysGroupedByPath();

        const existingEncKeyIds = new Set<string>();
        const pathsWithOldKeys: string[] = [];
        const physicalPathSuffix = `@${physicalPath}`;

        for (const [path, records] of Object.entries(grouped)) {
          if (path !== physicalPath && !path.endsWith(physicalPathSuffix)) {
            continue;
          }

          const encKeysAtPath = records.filter(
            (record) => typeof record?.use === "string" && record.use === "enc",
          );

          if (encKeysAtPath.length === 0) {
            continue;
          }

          pathsWithOldKeys.push(path);
          for (const record of encKeysAtPath) {
            if (typeof record?.kid === "string") {
              existingEncKeyIds.add(record.kid);
            }
          }
        }

        if (existingEncKeyIds.size > 0) {
          logger.debug("found_existing_encryption_keys_across_paths", {
            physical_path: physicalPath,
            paths_checked: pathsWithOldKeys,
            existing_enc_key_ids: Array.from(existingEncKeyIds),
          });

          const newEncKeyIds = new Set(
            validKeys
              .filter(
                (key) => typeof key?.use === "string" && key.use === "enc",
              )
              .map((key) => (typeof key?.kid === "string" ? key.kid : ""))
              .filter((kid): kid is string => kid.length > 0),
          );

          const keysToRemove = Array.from(existingEncKeyIds).filter(
            (kid) => !newEncKeyIds.has(kid),
          );

          if (keysToRemove.length > 0) {
            logger.info("removing_old_encryption_keys_for_key_rotation", {
              physical_path: physicalPath,
              paths_with_old_keys: pathsWithOldKeys,
              old_key_ids: keysToRemove,
              new_key_ids: Array.from(newEncKeyIds),
              origin,
            });

            for (const kid of keysToRemove) {
              await this.keyStore.removeKey(kid);
              logger.debug("removed_old_encryption_key_from_all_paths", {
                kid,
              });
            }
          }
        }
      } catch (error) {
        logger.warning("failed_to_remove_old_encryption_keys", {
          physical_path: physicalPath,
          error: error instanceof Error ? error.message : String(error),
          origin,
        });
      }
    }

    const addKeyOptions: {
      keys: Array<Record<string, unknown>>;
      physicalPath: string;
      systemId: string;
      origin: DeliveryOriginType;
      skipSidValidation?: boolean;
      sid?: string;
    } = {
      keys: validKeys,
      physicalPath,
      systemId,
      origin,
    };

    if (skipSidValidation) {
      addKeyOptions.skipSidValidation = true;
    }

    if (typeof sid === "string") {
      addKeyOptions.sid = sid;
    }

    await this.inner.addKeys(addKeyOptions);
  }

  public async announceKeysToUpstream(): Promise<void> {
    await this.inner.announceKeysToUpstream();
  }

  public async handleKeyRequest(options: {
    kid: string;
    fromSegment: string;
    physicalPath?: string;
    origin: DeliveryOriginType;
    correlationId?: string;
    originalClientSid?: string;
  }): Promise<void> {
    await this.inner.handleKeyRequest(options);
  }

  public async removeKeysForPath(physicalPath: string): Promise<number> {
    return this.inner.removeKeysForPath(physicalPath);
  }

  public async getKeysForPath(
    physicalPath: string,
  ): Promise<Iterable<KeyRecord>> {
    return this.inner.getKeysForPath(physicalPath);
  }

  public async purgeExpiredCertificates(): Promise<number> {
    logger.debug("certificate_purge_starting");

    const module = await loadX509Module();
    if (!module) {
      logger.warning("certificate_purge_skipped", {
        reason: "x509_module_unavailable",
      });
      return 0;
    }

    const now = new Date();
    const keysGrouped = await this.keyStore.getKeysGroupedByPath();
    const keysToRemove: Array<{ kid: string; physicalPath?: string }> = [];

    for (const keys of Object.values(keysGrouped)) {
      for (const key of keys) {
        const chain = (key as Record<string, unknown>).x5c;
        if (!Array.isArray(chain) || chain.length === 0) {
          continue;
        }

        const [leaf] = chain;
        if (typeof leaf !== "string") {
          continue;
        }

        try {
          const raw = decodeBase64Cert(leaf);
          const cert = new module.X509Certificate(raw);
          const expiration = cert.notAfter;

          if (expiration && expiration.getTime() < now.getTime()) {
            logger.debug("expired_certificate_found", {
              kid: typeof key.kid === "string" ? key.kid : "unknown",
              physical_path:
                typeof key.physical_path === "string"
                  ? key.physical_path
                  : "unknown",
              expired_at: expiration.toISOString(),
            });
            if (typeof key.kid === "string") {
              const removal: { kid: string; physicalPath?: string } = {
                kid: key.kid,
              };
              if (typeof key.physical_path === "string") {
                removal.physicalPath = key.physical_path;
              }
              keysToRemove.push(removal);
            }
          }
        } catch (error) {
          logger.warning("certificate_parsing_failed_during_purge", {
            kid: typeof key.kid === "string" ? key.kid : "unknown",
            error: error instanceof Error ? error.message : String(error),
            message: "Could not parse certificate for expiry check",
          });
        }
      }
    }

    let purgedCount = 0;
    for (const keyInfo of keysToRemove) {
      try {
        const removed = await this.keyStore.removeKey(keyInfo.kid);
        if (removed) {
          purgedCount += 1;
          logger.debug("expired_certificate_purged", {
            kid: keyInfo.kid,
            physical_path: keyInfo.physicalPath ?? "unknown",
          });
        }
      } catch (error) {
        logger.error("certificate_purge_failed", {
          kid: keyInfo.kid,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    logger.debug("certificate_purge_completed", {
      purged_count: purgedCount,
    });

    return purgedCount;
  }

  private startPurgeLoop(): void {
    if (this.purgeTask) {
      return;
    }

    this.purgeTask = this.spawn(
      async (signal) => {
        logger.debug("certificate_purge_loop_started", {
          interval_seconds: this.certPurgeInterval,
        });

        try {
          while (!signal?.aborted) {
            const waitPromise = new Promise<void>((resolve) => {
              const timeout = setTimeout(
                () => resolve(),
                this.certPurgeInterval * 1000,
              );
              if (signal) {
                signal.addEventListener(
                  "abort",
                  () => {
                    clearTimeout(timeout);
                    resolve();
                  },
                  { once: true },
                );
              }
            });

            await waitPromise;
            if (signal?.aborted) {
              break;
            }

            try {
              const purged = await this.purgeExpiredCertificates();
              if (purged > 0) {
                logger.debug("certificate_purge_cycle_completed", {
                  purged_count: purged,
                });
              }
            } catch (error) {
              logger.error("certificate_purge_cycle_failed", {
                error: error instanceof Error ? error.message : String(error),
              });
            }
          }
        } catch (error) {
          if (signal?.aborted) {
            logger.debug("certificate_purge_loop_cancelled");
          } else {
            logger.error("certificate_purge_loop_failed", {
              error: error instanceof Error ? error.message : String(error),
            });
          }
        } finally {
          logger.debug("certificate_purge_loop_stopped");
        }
      },
      { name: "cert-purge" },
    );
  }
}

type ValidationWrapperResult = {
  accepted: boolean;
  skip: boolean;
};

function validateJwkX5cCertificateWrapper(options: {
  jwk: Record<string, unknown>;
  trustStore: string;
  enforceNameConstraints: boolean;
  origin: DeliveryOriginType;
  systemId: string;
  physicalPath: string;
}): ValidationWrapperResult {
  const {
    jwk,
    trustStore,
    enforceNameConstraints,
    origin,
    systemId,
    physicalPath,
  } = options;

  let result: ValidateJwkX5cCertificateResult;
  try {
    result = validateJwkX5cCertificate({
      jwk,
      trustStorePem: trustStore,
      enforceNameConstraints,
      strict: false,
    });
  } catch (error) {
    logger.warning("rejected_key_due_to_certificate_validation_failure", {
      kid: typeof jwk.kid === "string" ? jwk.kid : "unknown",
      from_system_id: systemId,
      from_physical_path: physicalPath,
      origin,
      error: error instanceof Error ? error.message : String(error),
      scenario: "node_attach",
    });
    return {
      accepted: false,
      skip:
        origin === DeliveryOriginType.DOWNSTREAM ||
        origin === DeliveryOriginType.UPSTREAM,
    };
  }

  if (result.isValid) {
    return { accepted: true, skip: false };
  }

  logger.warning("rejected_key_due_to_certificate_validation_failure", {
    kid: typeof jwk.kid === "string" ? jwk.kid : "unknown",
    from_system_id: systemId,
    from_physical_path: physicalPath,
    origin,
    error: result.error ?? "unknown",
    scenario: "node_attach",
  });

  return {
    accepted: false,
    skip:
      origin === DeliveryOriginType.DOWNSTREAM ||
      origin === DeliveryOriginType.UPSTREAM,
  };
}

function resolveTrustStorePath(): string | null {
  try {
    if (typeof process === "undefined" || !process.env) {
      return null;
    }

    if (process.env.FAME_TRUST_STORE_PATH) {
      return process.env.FAME_TRUST_STORE_PATH;
    }

    return process.env.FAME_CA_CERT_FILE ?? null;
  } catch (error) {
    logger.debug("trust_store_resolution_failed", {
      error: error instanceof Error ? error.message : String(error),
    });
    return null;
  }
}
