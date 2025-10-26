import {
  KeyStore,
  getKeyStore,
  KeyStoreFactory,
  type KeyStoreConfig,
  KeyManagerFactory,
  KEY_MANAGER_FACTORY_BASE_TYPE,
  type KeyManagerConfig,
} from "@naylence/runtime";

import { X5CKeyManager, type X5CKeyManagerOptions } from "./x5c-key-manager.js";

export interface X5CKeyManagerConfig extends KeyManagerConfig {
  type: "X5CKeyManager";
  keyStore?: KeyStoreConfig | null;
  certPurgeIntervalSeconds?: number;
}

export const FACTORY_META = {
  base: KEY_MANAGER_FACTORY_BASE_TYPE,
  key: "X5CKeyManager",
} as const;

export class X5CKeyManagerFactory extends KeyManagerFactory<X5CKeyManagerConfig> {
  public readonly type = "X5CKeyManager";
  public readonly isDefault = true;
  public readonly priority = 100;

  public async create(
    config?: X5CKeyManagerConfig | Record<string, unknown> | null,
    keyStore?: KeyStore | null,
  ): Promise<X5CKeyManager> {
    const resolvedConfig: X5CKeyManagerConfig = {
      type: "X5CKeyManager",
      ...(config ?? {}),
    } as X5CKeyManagerConfig;

    let resolvedKeyStore: KeyStore | null = keyStore ?? null;

    if (!resolvedKeyStore && resolvedConfig.keyStore) {
      resolvedKeyStore = await KeyStoreFactory.createKeyStore(
        resolvedConfig.keyStore,
      );
    }

    if (!resolvedKeyStore) {
      resolvedKeyStore = getKeyStore();
    }

    const options: X5CKeyManagerOptions =
      typeof resolvedConfig.certPurgeIntervalSeconds === "number"
        ? {
            keyStore: resolvedKeyStore,
            certPurgeIntervalSeconds: resolvedConfig.certPurgeIntervalSeconds,
          }
        : { keyStore: resolvedKeyStore };

    return new X5CKeyManager(options);
  }
}

export default X5CKeyManagerFactory;
