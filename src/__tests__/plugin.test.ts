import { jest } from "@jest/globals";

import { FACTORY_META as DEFAULT_CA_SERVICE_FACTORY_META } from "../naylence/fame/security/cert/default-ca-service-factory.js";
import { FACTORY_META as DEFAULT_CERTIFICATE_MANAGER_FACTORY_META } from "../naylence/fame/security/cert/default-certificate-manager-factory.js";
import { FACTORY_META as CHANNEL_ENCRYPTION_FACTORY_META } from "../naylence/fame/security/encryption/channel/channel-encryption-manager-factory.js";
import { FACTORY_META as COMPOSITE_ENCRYPTION_FACTORY_META } from "../naylence/fame/security/encryption/composite-encryption-manager-factory.js";
import { FACTORY_META as DEFAULT_SECURE_CHANNEL_FACTORY_META } from "../naylence/fame/security/encryption/default-secure-channel-manager-factory.js";
import { FACTORY_META as X25519_ENCRYPTION_FACTORY_META } from "../naylence/fame/security/encryption/sealed/x25519-encryption-manager-factory.js";
import { FACTORY_META as X5C_KEY_MANAGER_FACTORY_META } from "../naylence/fame/security/keys/x5c-key-manager-factory.js";
import { FACTORY_META as EDDSA_SIGNER_FACTORY_META } from "../naylence/fame/security/signing/eddsa-envelope-signer-factory.js";
import { FACTORY_META as EDDSA_VERIFIER_FACTORY_META } from "../naylence/fame/security/signing/eddsa-envelope-verifier-factory.js";
import { FACTORY_META as AFT_LOAD_BALANCER_FACTORY_META } from "../naylence/fame/stickiness/aft-load-balancer-stickiness-manager-factory.js";
import { FACTORY_META as AFT_REPLICA_FACTORY_META } from "../naylence/fame/stickiness/aft-replica-stickiness-manager-factory.js";
import { FACTORY_META as ADVANCED_WELCOME_FACTORY_META } from "../naylence/fame/welcome/advanced-welcome-service-factory.js";

const expectedFactories = [
  {
    base: DEFAULT_CA_SERVICE_FACTORY_META.base,
    key: DEFAULT_CA_SERVICE_FACTORY_META.key,
  },
  {
    base: DEFAULT_CERTIFICATE_MANAGER_FACTORY_META.base,
    key: DEFAULT_CERTIFICATE_MANAGER_FACTORY_META.key,
  },
  {
    base: CHANNEL_ENCRYPTION_FACTORY_META.base,
    key: CHANNEL_ENCRYPTION_FACTORY_META.key,
  },
  {
    base: COMPOSITE_ENCRYPTION_FACTORY_META.base,
    key: COMPOSITE_ENCRYPTION_FACTORY_META.key,
  },
  {
    base: DEFAULT_SECURE_CHANNEL_FACTORY_META.base,
    key: DEFAULT_SECURE_CHANNEL_FACTORY_META.key,
  },
  {
    base: X25519_ENCRYPTION_FACTORY_META.base,
    key: X25519_ENCRYPTION_FACTORY_META.key,
  },
  {
    base: X5C_KEY_MANAGER_FACTORY_META.base,
    key: X5C_KEY_MANAGER_FACTORY_META.key,
  },
  { base: EDDSA_SIGNER_FACTORY_META.base, key: EDDSA_SIGNER_FACTORY_META.key },
  {
    base: EDDSA_VERIFIER_FACTORY_META.base,
    key: EDDSA_VERIFIER_FACTORY_META.key,
  },
  {
    base: AFT_LOAD_BALANCER_FACTORY_META.base,
    key: AFT_LOAD_BALANCER_FACTORY_META.key,
  },
  { base: AFT_REPLICA_FACTORY_META.base, key: AFT_REPLICA_FACTORY_META.key },
  {
    base: ADVANCED_WELCOME_FACTORY_META.base,
    key: ADVANCED_WELCOME_FACTORY_META.key,
  },
];

describe("advanced security plugin", () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  it("registers advanced security and supplemental factories", async () => {
    const { registerAdvancedSecurityPluginFactories } = await import(
      "../plugin.js"
    );

    const registrations: Array<{ base: string; key: string }> = [];
    const registrar = {
      registerFactory: jest.fn((base: string, key: string) => {
        registrations.push({ base, key });
      }),
    };

    await registerAdvancedSecurityPluginFactories(registrar);

    expect(registrar.registerFactory).toHaveBeenCalledTimes(
      expectedFactories.length,
    );
    for (const expected of expectedFactories) {
      expect(registrations).toEqual(
        expect.arrayContaining([expect.objectContaining(expected)]),
      );
    }
  });

  it("registers factories only once", async () => {
    const factoryModule = await import("@naylence/factory");
    const registerSpy = jest
      .spyOn(factoryModule.Registry, "registerFactory")
      .mockImplementation(() => undefined);

    const pluginModule = await import("../plugin.js");

    await pluginModule.default.register();
    const firstCallCount = registerSpy.mock.calls.length;
    expect(firstCallCount).toBeGreaterThan(0);

    await pluginModule.default.register();
    expect(registerSpy.mock.calls.length).toBe(firstCallCount);

    registerSpy.mockRestore();
  });

  it("exposes the plugin specifier", async () => {
    const pluginModule = await import("../plugin.js");
    expect(pluginModule.ADVANCED_SECURITY_PLUGIN_SPECIFIER).toBe(
      pluginModule.default.name,
    );
  });
});
