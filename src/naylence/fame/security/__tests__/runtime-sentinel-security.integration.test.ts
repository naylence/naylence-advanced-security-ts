/**
 * Runtime security integration test copied from naylence-runtime-ts to verify
 * that basic security functionality works correctly in advanced-security-ts
 * with both runtime and advanced-security factories registered.
 */
import {
  DeliveryOriginType,
  formatAddress,
  type AuthorizationContext,
  type FameDeliveryContext,
  type FameEnvelope,
} from "naylence-core";

import { SignJWT } from "jose";

import {
  DefaultHttpServer,
  getWebsocketListenerInstance,
  NodeFactory,
  type FameNode,
  SentinelFactory,
  type RouteManager,
  type Sentinel,
  DefaultSecurityManager,
  DefaultCryptoProvider,
  type CryptoProvider,
  getKeyStore,
  type KeyManager,
  type KeyRecord,
  basicConfig,
  LogLevel,
} from "naylence-runtime";

jest.setTimeout(20000);

const SOCKET_HOST = "127.0.0.1";
const WAIT_TIMEOUT_MS = 10_000;
const WAIT_INTERVAL_MS = 50;
const SYSTEM_INBOX = "__sys__";

interface SecurityConfigOverrides {
  cryptoProvider?: CryptoProvider | null;
}

interface GatedSecurityConfigOptions extends SecurityConfigOverrides {
  issuer: string;
  hmacSecret: string;
  audience?: string;
  requiredScopes?: string[];
}

function createSecurityConfig(): Record<string, unknown> {
  return {
    type: "DefaultSecurityManager",
    authorizer: { type: "NoopAuthorizer" },
    security_policy: {
      type: "NoSecurityPolicy",
    },
  } satisfies Record<string, unknown>;
}

function applySecurityConfigOverrides(
  config: Record<string, unknown>,
  overrides?: SecurityConfigOverrides
): Record<string, unknown> {
  if (!overrides) {
    return config;
  }

  if ("cryptoProvider" in overrides) {
    (config as Record<string, unknown>).cryptoProvider = overrides.cryptoProvider ?? null;
    (config as Record<string, unknown>).crypto_provider = overrides.cryptoProvider ?? null;
  }

  return config;
}

function createOverlaySecurityConfig(overrides?: SecurityConfigOverrides): Record<string, unknown> {
  const baseConfig = {
    type: "DefaultSecurityManager",
    authorizer: { type: "NoopAuthorizer" },
    security_policy: {
      type: "DefaultSecurityPolicy",
      signing: {
        outbound: {
          defaultSigning: true,
          signSensitiveOperations: true,
          signIfRecipientExpects: true,
        },
        response: {
          mirrorRequestSigning: true,
          alwaysSignResponses: true,
          signErrorResponses: true,
        },
        inbound: {
          signaturePolicy: "optional",
          unsignedViolationAction: "nack",
          missingKeyAction: "nack",
          invalidSignatureAction: "reject",
        },
        signingMaterial: "raw-key",
      },
      encryption: {
        outbound: {
          defaultLevel: "plaintext",
          escalateIfPeerSupports: true,
          preferSealedForSensitive: true,
        },
        response: {
          minimumResponseLevel: "plaintext",
          mirrorRequestLevel: true,
          escalateSealedResponses: true,
        },
        inbound: {
          allowPlaintext: false,
          allowChannel: true,
          allowSealed: true,
          plaintextViolationAction: "nack",
        },
      },
    },
    key_manager_config: {
      type: "DefaultKeyManager",
    },
    key_validator: { type: "NoopKeyValidator" },
  } satisfies Record<string, unknown>;

  return applySecurityConfigOverrides(baseConfig, overrides);
}

function createSigningOverlaySecurityConfig(
  overrides?: SecurityConfigOverrides
): Record<string, unknown> {
  const config = createOverlaySecurityConfig(overrides);
  const securityPolicy = (config.security_policy ?? {}) as Record<string, unknown>;
  const encryption = { ...(securityPolicy.encryption as Record<string, unknown> | undefined) };

  encryption.outbound = {
    ...((encryption.outbound as Record<string, unknown> | undefined) ?? {}),
    defaultLevel: "plaintext",
    escalateIfPeerSupports: false,
    preferSealedForSensitive: false,
  } satisfies Record<string, unknown>;

  encryption.response = {
    ...((encryption.response as Record<string, unknown> | undefined) ?? {}),
    minimumResponseLevel: "plaintext",
    mirrorRequestLevel: false,
    escalateSealedResponses: false,
  } satisfies Record<string, unknown>;

  encryption.inbound = {
    ...((encryption.inbound as Record<string, unknown> | undefined) ?? {}),
    allowPlaintext: true,
    plaintextViolationAction: "allow",
  } satisfies Record<string, unknown>;

  securityPolicy.encryption = encryption;
  config.security_policy = securityPolicy;

  return applySecurityConfigOverrides(config, overrides);
}

function createGatedSecurityConfig(options: GatedSecurityConfigOptions): Record<string, unknown> {
  const {
    issuer,
    hmacSecret,
    audience,
    requiredScopes = ["node.connect"],
    cryptoProvider,
  } = options;

  const securityPolicy: Record<string, unknown> = {
    type: "DefaultSecurityPolicy",
    signing: {
      inbound: {
        signaturePolicy: "disabled",
        unsignedViolationAction: "allow",
        invalidSignatureAction: "allow",
      },
      response: {
        mirrorRequestSigning: false,
        alwaysSignResponses: false,
        signErrorResponses: false,
      },
      outbound: {
        defaultSigning: false,
        signSensitiveOperations: false,
        signIfRecipientExpects: false,
      },
    },
    encryption: {
      inbound: {
        allowPlaintext: true,
        allowChannel: false,
        allowSealed: false,
        plaintextViolationAction: "allow",
        channelViolationAction: "nack",
        sealedViolationAction: "nack",
      },
      response: {
        mirrorRequestLevel: true,
        minimumResponseLevel: "plaintext",
        escalateSealedResponses: false,
      },
      outbound: {
        defaultLevel: "plaintext",
        escalateIfPeerSupports: false,
        preferSealedForSensitive: false,
      },
    },
  } satisfies Record<string, unknown>;

  const authorizer: Record<string, unknown> = {
    type: "OAuth2Authorizer",
    issuer,
    required_scopes: requiredScopes,
    require_scope: true,
    algorithm: "HS256",
    token_verifier_config: {
      type: "JWTTokenVerifier",
      issuer,
      algorithms: ["HS256"],
      hmac_secret: hmacSecret,
      ttl_sec: 3600,
    },
  } satisfies Record<string, unknown>;

  if (audience) {
    authorizer.audience = audience;
  }

  const config: Record<string, unknown> = {
    type: "DefaultSecurityManager",
    security_policy: securityPolicy,
    authorizer,
  };

  const overrides = cryptoProvider !== undefined ? { cryptoProvider } : undefined;
  return applySecurityConfigOverrides(config, overrides);
}

async function waitForCondition(
  predicate: () => boolean,
  timeoutMs = WAIT_TIMEOUT_MS
): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      if (predicate()) {
        return;
      }
    } catch {
      // Ignore transient predicate errors while waiting.
    }

    await new Promise((resolve) => {
      setTimeout(resolve, WAIT_INTERVAL_MS);
    });
  }

  throw new Error("Timed out waiting for condition");
}

function toKeyArray(
  candidate: Record<string, unknown> | Array<Record<string, unknown>> | undefined | null
): Array<Record<string, unknown>> {
  if (!candidate) {
    return [];
  }
  return Array.isArray(candidate) ? candidate : [candidate];
}

async function waitForKeysForPath(
  manager: { getKeysForPath(path: string): Promise<Iterable<KeyRecord>> },
  path: string,
  minimumCount = 1,
  timeoutMs = WAIT_TIMEOUT_MS
): Promise<Array<KeyRecord>> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    // eslint-disable-next-line no-await-in-loop
    const iterable = await manager.getKeysForPath(path);
    const keys = Array.from(iterable) as Array<KeyRecord>;
    if (keys.length >= minimumCount) {
      return keys;
    }

    // eslint-disable-next-line no-await-in-loop
    await new Promise((resolve) => {
      setTimeout(resolve, WAIT_INTERVAL_MS);
    });
  }

  const keyStore = getKeyStore();
  const allKeys = Array.from(await keyStore.getKeys()) as Array<KeyRecord>;
  // eslint-disable-next-line no-console
  console.error("waitForKeysForPath timeout debug", {
    path,
    available: allKeys.map((key) => ({
      kid: key.kid,
      physical_path: key.physical_path,
      use: key.use,
    })),
  });

  throw new Error(`Timed out waiting for keys at path ${path}`);
}

describe("Runtime Sentinel security integration (in advanced-security-ts)", () => {
  beforeAll(() => {
    basicConfig({ level: LogLevel.ERROR });
  });

  afterEach(async () => {
    await DefaultHttpServer.shutdownAll();
  });

  test("downstream node exchanges overlay security keys during attach", async () => {
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;

    try {
      const parentCryptoProvider = await DefaultCryptoProvider.create({
        issuer: "test.naylence.runtime.parent",
        audience: "integration-tests-parent",
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: "parent-overlay-sentinel",
        security: createOverlaySecurityConfig({ cryptoProvider: parentCryptoProvider }),
        admission: {
          type: "NoopAdmissionClient",
          autoAcceptLogicals: true,
        },
        delivery: {
          type: "AtLeastOnceDeliveryPolicy",
        },
        routingPolicy: {
          type: "CompositeRoutingPolicy",
        },
        listeners: [
          {
            type: "WebSocketListener",
            host: SOCKET_HOST,
            port: 0,
          },
        ],
      });

      await parent.start();

      const serverListener = getWebsocketListenerInstance();
      expect(serverListener).toBeTruthy();

      await waitForCondition(() => Boolean(serverListener?.baseUrl));

      const baseUrl = serverListener?.baseUrl;
      expect(baseUrl).toBeTruthy();

      const wsBaseUrl = baseUrl!.startsWith("https://")
        ? baseUrl!.replace("https://", "wss://")
        : baseUrl!.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: "test.naylence.runtime.child",
        audience: "integration-tests-child",
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: "child-overlay-node",
        hasParent: true,
        requestedLogicals: ["svc"],
        security: createOverlaySecurityConfig({ cryptoProvider: childCryptoProvider }),
        delivery: {
          type: "AtLeastOnceDeliveryPolicy",
        },
        admission: {
          type: "DirectAdmissionClient",
          connectionGrants: [
            {
              type: "WebSocketConnectionGrant",
              purpose: "node.attach",
              url: downstreamAttachUrl,
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();

      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager }).routeManager;
      await waitForCondition(() => routeManager.downstreamRoutes.has(child!.id));

      expect(child?.physicalPath).toMatch(/^\//);

      const parentSecurity = parent.securityManager;
      const childSecurity = child.securityManager;

      expect(parentSecurity).toBeInstanceOf(DefaultSecurityManager);
      expect(childSecurity).toBeInstanceOf(DefaultSecurityManager);

      const parentOverlayManager = parentSecurity as DefaultSecurityManager;
      const childOverlayManager = childSecurity as DefaultSecurityManager;

      expect(parentOverlayManager.supportsOverlaySecurity).toBe(true);
      expect(childOverlayManager.supportsOverlaySecurity).toBe(true);

      const parentShareableKeys = toKeyArray(parentOverlayManager.getShareableKeys());
      const childShareableKeys = toKeyArray(childOverlayManager.getShareableKeys());

      expect(parentShareableKeys.length).toBeGreaterThan(0);
      expect(childShareableKeys.length).toBeGreaterThan(0);

      const parentKeyManager = parentOverlayManager.keyManager as KeyManager | null;
      const childKeyManager = childOverlayManager.keyManager as KeyManager | null;

      expect(parentKeyManager).toBeTruthy();
      expect(childKeyManager).toBeTruthy();

      if (!parentKeyManager || !childKeyManager) {
        throw new Error("Overlay security key managers must be available");
      }

      const childInternalStore =
        (childKeyManager as unknown as { keyStore?: unknown }).keyStore ?? null;
      if (
        childInternalStore &&
        typeof (childInternalStore as { getKeys?: () => Promise<Iterable<KeyRecord>> }).getKeys ===
          "function"
      ) {
        const rawKeysIterable = await (
          childInternalStore as { getKeys: () => Promise<Iterable<KeyRecord>> }
        ).getKeys();
        // eslint-disable-next-line no-console
        console.log("child key store snapshot", Array.from(rawKeysIterable));
      } else {
        // eslint-disable-next-line no-console
        console.log("child key store snapshot unavailable");
      }

      // eslint-disable-next-line no-console
      console.log("overlay key debug", {
        parentPath: parent!.physicalPath,
        childPath: child!.physicalPath,
        parentShareable: parentShareableKeys
          .map((key) => key.kid)
          .filter((kid): kid is string => typeof kid === "string"),
        childShareable: childShareableKeys
          .map((key) => key.kid)
          .filter((kid): kid is string => typeof kid === "string"),
      });

      // eslint-disable-next-line no-console
      console.log(
        "child keys for parent path (immediate)",
        Array.from(await childKeyManager.getKeysForPath(parent!.physicalPath))
      );

      const parentStoredKeys = await waitForKeysForPath(parentKeyManager, child!.physicalPath);
      const childStoredKeys = await waitForKeysForPath(childKeyManager, parent!.physicalPath);

      expect(parentStoredKeys.length).toBeGreaterThanOrEqual(2);
      expect(childStoredKeys.length).toBeGreaterThanOrEqual(2);

      const parentHasSigningKey = parentStoredKeys.some((key) => key.crv === "Ed25519");
      const parentHasEncryptionKey = parentStoredKeys.some((key) => key.crv === "X25519");
      const childHasSigningKey = childStoredKeys.some((key) => key.crv === "Ed25519");
      const childHasEncryptionKey = childStoredKeys.some((key) => key.crv === "X25519");

      expect(parentHasSigningKey).toBe(true);
      expect(parentHasEncryptionKey).toBe(true);
      expect(childHasSigningKey).toBe(true);
      expect(childHasEncryptionKey).toBe(true);

      const parentStoredKeysMatch = parentStoredKeys.every((key) => {
        return typeof key.physical_path === "string" && key.physical_path === child!.physicalPath;
      });
      const childStoredKeysMatch = childStoredKeys.every((key) => {
        return typeof key.physical_path === "string" && key.physical_path === parent!.physicalPath;
      });

      expect(parentStoredKeysMatch).toBe(true);
      expect(childStoredKeysMatch).toBe(true);

      const parentKeyIds = parentShareableKeys
        .map((key) => key.kid)
        .filter((kid): kid is string => typeof kid === "string");
      const childKeyIds = childShareableKeys
        .map((key) => key.kid)
        .filter((kid): kid is string => typeof kid === "string");

      for (const kid of parentKeyIds) {
        // eslint-disable-next-line no-await-in-loop
        expect(await childKeyManager.hasKey(kid)).toBe(true);
      }

      for (const kid of childKeyIds) {
        // eslint-disable-next-line no-await-in-loop
        expect(await parentKeyManager.hasKey(kid)).toBe(true);
      }
    } finally {
      await Promise.allSettled([child?.stop(), parent?.stop()]);
    }
  });
});
