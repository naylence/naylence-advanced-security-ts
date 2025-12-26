/**
 * Incremental strict-overlay security integration tests.
 * Starting from the working NoopAuthorizer test and progressively adding
 * strict-overlay features to identify the exact failure point.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  DeliveryOriginType,
  formatAddress,
  type FameAddress,
  type FameDeliveryContext,
  type FameEnvelope,
} from "@naylence/core";
import { SignJWT, exportJWK, generateKeyPair } from "jose";

import {
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
  LogLevel,
  basicConfig,
} from "@naylence/runtime";

import {
  DefaultHttpServer,
  getWebsocketListenerInstance,
} from "@naylence/runtime/node";

import {
  setupTestCACredentials,
  type TestCACredentials,
} from "./test-ca-helpers.js";

jest.setTimeout(20000);

const SOCKET_HOST = "127.0.0.1";
const WAIT_TIMEOUT_MS = 10_000;
const WAIT_INTERVAL_MS = 50;

interface SecurityConfigOverrides {
  cryptoProvider?: CryptoProvider | null;
}

function applySecurityConfigOverrides(
  config: Record<string, unknown>,
  overrides?: SecurityConfigOverrides,
): Record<string, unknown> {
  if (!overrides) {
    return config;
  }

  if ("cryptoProvider" in overrides) {
    (config as Record<string, unknown>).cryptoProvider =
      overrides.cryptoProvider ?? null;
    (config as Record<string, unknown>).crypto_provider =
      overrides.cryptoProvider ?? null;
  }

  return config;
}

async function waitForCondition(
  predicate: () => boolean,
  timeoutMs = WAIT_TIMEOUT_MS,
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

async function waitForKeysForPath(
  manager: { getKeysForPath(path: string): Promise<Iterable<KeyRecord>> },
  path: string,
  minimumCount = 1,
  timeoutMs = WAIT_TIMEOUT_MS,
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

  throw new Error(`Timed out waiting for keys at path ${path}`);
}

describe("Incremental strict-overlay security integration", () => {
  let suiteCaCredentials: TestCACredentials | null = null;

  beforeAll(async () => {
    basicConfig({ level: LogLevel.ERROR });
    suiteCaCredentials = await setupTestCACredentials();
  });

  afterEach(async () => {
    await DefaultHttpServer.shutdownAll();
  });

  afterAll(async () => {
    if (suiteCaCredentials) {
      await suiteCaCredentials.cleanup();
      suiteCaCredentials = null;
    }
  });

  test("Step 1: Working baseline - NoopAuthorizer with overlay security", async () => {
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;

    try {
      const parentCryptoProvider = await DefaultCryptoProvider.create({
        issuer: "test.step1.parent",
        audience: "step1-parent",
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: "step1-sentinel",
        security: {
          type: "DefaultSecurityManager",
          authorizer: { type: "NoopAuthorizer" },
          cryptoProvider: parentCryptoProvider,
          crypto_provider: parentCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
                unsignedViolationAction: "nack",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
                allowChannel: true,
                allowSealed: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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

      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: "test.step1.child",
        audience: "step1-child",
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: "step1-client",
        hasParent: true,
        requestedLogicals: ["svc"],
        security: {
          type: "DefaultSecurityManager",
          authorizer: { type: "NoopAuthorizer" },
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);
      expect(parent.securityManager).toBeInstanceOf(DefaultSecurityManager);
      expect(child.securityManager).toBeInstanceOf(DefaultSecurityManager);
    } finally {
      if (child) {
        await child.stop();
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
      if (parent) {
        await parent.stop();
      }
    }
  });

  test("Step 2: Add JWT token but keep NoopAuthorizer", async () => {
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;
    let jwksServer: http.Server | null = null;

    try {
      const issuer = "https://step2.integration";
      const sentinelId = "step2-sentinel";
      const childId = "step2-client";

      // Set up JWKS server (but won't actually use it with NoopAuthorizer)
      const { publicKey, privateKey } = await generateKeyPair("RS256");
      const jwk = await exportJWK(publicKey);
      jwk.kid = jwk.kid ?? "step2-key";
      const jwksBody = JSON.stringify({ keys: [jwk] });

      jwksServer = http.createServer((req, res) => {
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(jwksBody);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        jwksServer!.listen(0, "127.0.0.1", resolve);
      });
      const address = jwksServer.address() as AddressInfo;
      const jwksUrl = `http://127.0.0.1:${address.port}/keys`;

      const parentCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/sentinel`,
        audience: `${sentinelId}.step2`,
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: sentinelId,
        security: {
          type: "DefaultSecurityManager",
          authorizer: { type: "NoopAuthorizer" }, // Still using Noop
          cryptoProvider: parentCryptoProvider,
          crypto_provider: parentCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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
      await waitForCondition(() => Boolean(serverListener?.baseUrl));
      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      // Create JWT token (will be sent but not validated)
      const attachToken = await new SignJWT({
        scope: "node.connect",
        capabilities: ["node.connect"],
      })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience([sentinelId])
        .setSubject(childId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/node`,
        audience: `${childId}.step2`,
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: childId,
        hasParent: true,
        requestedLogicals: ["svc"],
        security: {
          type: "DefaultSecurityManager",
          authorizer: { type: "NoopAuthorizer" },
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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
              auth: {
                type: "BearerTokenHeaderAuth",
                tokenProvider: {
                  type: "StaticTokenProvider",
                  token: attachToken,
                },
              },
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();
      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);
    } finally {
      if (child) {
        await child.stop();
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
      if (parent) {
        await parent.stop();
      }
      if (jwksServer) {
        await new Promise<void>((resolve) =>
          jwksServer!.close(() => resolve()),
        );
      }
    }
  });

  test("Step 3: Add DefaultAuthorizer with JWT verification", async () => {
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;
    let jwksServer: http.Server | null = null;

    try {
      const issuer = "https://step3.integration";
      const sentinelId = "step3-sentinel";
      const childId = "step3-client";

      const { publicKey, privateKey } = await generateKeyPair("RS256");
      const jwk = await exportJWK(publicKey);
      jwk.kid = jwk.kid ?? "step3-key";
      const jwksBody = JSON.stringify({ keys: [jwk] });

      jwksServer = http.createServer((req, res) => {
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(jwksBody);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        jwksServer!.listen(0, "127.0.0.1", resolve);
      });
      const address = jwksServer.address() as AddressInfo;
      const jwksUrl = `http://127.0.0.1:${address.port}/keys`;

      const parentCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/sentinel`,
        audience: `${sentinelId}.step3`,
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: sentinelId,
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
        },
        security: {
          type: "DefaultSecurityManager",
          authorizer: {
            type: "DefaultAuthorizer",
            verifier: {
              type: "JWKSJWTTokenVerifier",
              jwks_url: jwksUrl,
              issuer: issuer,
            },
          },
          cryptoProvider: parentCryptoProvider,
          crypto_provider: parentCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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
      await waitForCondition(() => Boolean(serverListener?.baseUrl));
      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      // Wait for parent physical path to be available
      await waitForCondition(() => Boolean(parent?.physicalPath));

      const attachToken = await new SignJWT({
        scope: "node.connect",
        capabilities: ["node.connect"],
      })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience([parent!.physicalPath!, sentinelId]) // Include physical path
        .setSubject(childId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/node`,
        audience: `${childId}.step3`,
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: childId,
        hasParent: true,
        requestedLogicals: ["svc"],
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
        },
        security: {
          type: "DefaultSecurityManager",
          authorizer: { type: "NoopAuthorizer" },
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
          security_policy: {
            type: "DefaultSecurityPolicy",
            signing: {
              signingMaterial: "raw-key",
              inbound: {
                signaturePolicy: "optional",
              },
              outbound: {
                defaultSigning: true,
              },
            },
            encryption: {
              inbound: {
                allowPlaintext: true,
              },
              outbound: {
                defaultLevel: "plaintext",
              },
            },
          },
        },
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
              auth: {
                type: "BearerTokenHeaderAuth",
                tokenProvider: {
                  type: "StaticTokenProvider",
                  token: attachToken,
                },
              },
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();
      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);
    } finally {
      if (child) {
        await child.stop();
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
      if (parent) {
        await parent.stop();
      }
      if (jwksServer) {
        await new Promise<void>((resolve) =>
          jwksServer!.close(() => resolve()),
        );
      }
    }
  });

  test("Step 4: Use SecurityProfile strict-overlay (X.509 certificates)", async () => {
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;
    let jwksServer: http.Server | null = null;

    try {
      const issuer = "https://step4.integration";
      const sentinelId = "step4-sentinel";
      const childId = "step4-client";

      const caCredentials = suiteCaCredentials;
      if (!caCredentials) {
        throw new Error("Test CA credentials were not initialized");
      }

      const { publicKey, privateKey } = await generateKeyPair("RS256");
      const jwk = await exportJWK(publicKey);
      jwk.kid = jwk.kid ?? "step4-key";
      const jwksBody = JSON.stringify({ keys: [jwk] });

      jwksServer = http.createServer((req, res) => {
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(jwksBody);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        jwksServer!.listen(0, "127.0.0.1", resolve);
      });
      const address = jwksServer.address() as AddressInfo;
      const jwksUrl = `http://127.0.0.1:${address.port}/keys`;

      // IMPORTANT: Create crypto provider with the same key that the certificate uses
      // Since we're using root CA cert as a workaround, we need to use the root CA key
      // In production, the CA would issue a cert for the node's actual signing key
      const sentinelCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/sentinel`,
        audience: `${sentinelId}.step4`,
        ttlSec: 600,
        algorithm: "EdDSA", // Explicitly set EdDSA algorithm
        signaturePrivatePem: caCredentials.rootKeyPem, // Use the root CA private key
        signaturePublicPem: caCredentials.rootPublicKeyPem, // Use the root CA public key
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: sentinelId,
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "plaintext", // Keep plaintext for now
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // X.509 certificate signing
          cryptoProvider: sentinelCryptoProvider,
          crypto_provider: sentinelCryptoProvider,
        },
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
      await waitForCondition(() => Boolean(serverListener?.baseUrl));
      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      const attachToken = await new SignJWT({
        scope: "node.connect",
        capabilities: ["node.connect"],
        // NOTE: No accepted_logicals - testing physical connection only
      })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience([parent.physicalPath ?? sentinelId, sentinelId])
        .setSubject(childId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

      // Create child crypto provider with the same root CA key (workaround)
      // In production, child would have its own key and request a cert from CA
      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/node`,
        audience: `${childId}.step4`,
        ttlSec: 600,
        algorithm: "EdDSA", // Explicitly set EdDSA algorithm
        signaturePrivatePem: caCredentials.rootKeyPem, // Use the root CA private key
        signaturePublicPem: caCredentials.rootPublicKeyPem, // Use the root CA public key
      });

      child = await nodeFactory.create({
        type: "Node",
        id: childId,
        hasParent: true,
        // NOTE: No requestedLogicals - testing physical connection only with X.509 signing
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "plaintext",
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // X.509 certificate signing
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
        },
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
              auth: {
                type: "BearerTokenHeaderAuth",
                tokenProvider: {
                  type: "StaticTokenProvider",
                  token: attachToken,
                },
              },
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();
      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);
      expect(parent.securityManager).toBeInstanceOf(DefaultSecurityManager);
      expect(child.securityManager).toBeInstanceOf(DefaultSecurityManager);
    } finally {
      // Clean up in proper order to avoid resource leaks:
      // 1. Stop child and wait for full cleanup
      if (child) {
        await child.stop();
        // Wait for connector cleanup to complete (receive-loop has 1000ms shutdown timeout)
        await new Promise((resolve) => setTimeout(resolve, 1200));
      }

      // 2. Stop parent (which hosts the HTTP server)
      if (parent) {
        await parent.stop();
      }

      // 3. Clean up other resources
      if (jwksServer) {
        await new Promise<void>((resolve) =>
          jwksServer!.close(() => resolve()),
        );
      }
    }
  });

  test("Step 5: Enable channel encryption (strict-overlay with X.509) - REQUIRES CA SERVICE", async () => {
    // NOTE: This test depends on Step 4 working, which requires CA service infrastructure.
    // See Step 4 test comments for details on what needs to be ported.
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;
    let jwksServer: http.Server | null = null;

    try {
      const issuer = "https://step5.integration";
      const sentinelId = "step5-sentinel";
      const childId = "step5-client";
      const caCredentials = suiteCaCredentials;
      if (!caCredentials) {
        throw new Error("Test CA credentials were not initialized");
      }

      const { publicKey, privateKey } = await generateKeyPair("RS256");
      const jwk = await exportJWK(publicKey);
      jwk.kid = jwk.kid ?? "step5-key";
      const jwksBody = JSON.stringify({ keys: [jwk] });

      jwksServer = http.createServer((req, res) => {
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(jwksBody);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        jwksServer!.listen(0, "127.0.0.1", resolve);
      });
      const address = jwksServer.address() as AddressInfo;
      const jwksUrl = `http://127.0.0.1:${address.port}/keys`;

      const sentinelCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/sentinel`,
        audience: `${sentinelId}.step5`,
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: sentinelId,
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "channel", // NOW ENABLE CHANNEL ENCRYPTION
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // DefaultCertificateManager should auto-activate for X.509
          cryptoProvider: sentinelCryptoProvider,
          crypto_provider: sentinelCryptoProvider,
        },
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
      await waitForCondition(() => Boolean(serverListener?.baseUrl));
      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      const attachToken = await new SignJWT({
        scope: "node.connect",
        capabilities: ["node.connect"],
        accepted_logicals: ["svc"],
      })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience([parent.physicalPath ?? sentinelId, sentinelId])
        .setSubject(childId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/node`,
        audience: `${childId}.step5`,
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: childId,
        hasParent: true,
        requestedLogicals: ["svc"],
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "channel",
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // X.509 certificate signing
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
          // Runtime auto-creates certificate manager for x509-chain signing
        },
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
              auth: {
                type: "BearerTokenHeaderAuth",
                tokenProvider: {
                  type: "StaticTokenProvider",
                  token: attachToken,
                },
              },
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();
      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);

      // Send a test message to verify channel encryption is actually enabled
      const testData = {
        test: "encryption-verification",
        timestamp: Date.now(),
      };
      const testEnvelope = child.envelopeFactory.createEnvelope({
        frame: {
          type: "Data",
          codec: "json",
          payload: testData,
        },
        to: formatAddress("__sys__", parent.physicalPath!), // Send to parent's system inbox
      });

      // Debug: Check security manager components
      const childSm = child.securityManager as DefaultSecurityManager;
      console.error("[DEBUG] Child security manager components:");
      console.error("  policy:", childSm?.policy?.constructor?.name ?? "null");
      console.error("  _keyManager:", Boolean((childSm as unknown as Record<string, unknown>)?._keyManager));
      console.error("  _encryptionManager:", Boolean((childSm as unknown as Record<string, unknown>)?._encryptionManager));
      console.error("  _envelopeSecurityHandler:", Boolean((childSm as unknown as Record<string, unknown>)?._envelopeSecurityHandler));
      console.error("  _keyManagementHandler:", Boolean((childSm as unknown as Record<string, unknown>)?._keyManagementHandler));
      if (childSm?.policy) {
        const reqs = childSm.policy.requirements?.();
        console.error("  policy.requirements():", JSON.stringify(reqs, null, 2).substring(0, 500));
        // Check policy encryption property 
        const policyAsAny = childSm.policy as unknown as { encryption?: { outbound?: { defaultLevel?: string } } };
        console.error("  policy.encryption?.outbound?.defaultLevel:", policyAsAny?.encryption?.outbound?.defaultLevel);
      }

      // Track encryption by checking security handler logs
      let encryptionApplied = false;
      let capturedLogs: string[] = [];
      let allLogs: string[] = [];
      basicConfig({ level: LogLevel.DEBUG });
      const logSpy = jest
        .spyOn(console, "log")
        .mockImplementation((message) => {
          if (typeof message === "string") {
            allLogs.push(message);
            if (message.includes("outbound_crypto_level_decided")) {
              capturedLogs.push(message);
              if (message.includes("crypto_level=channel")) {
                encryptionApplied = true;
              }
            }
          }
        });

      await child.send(testEnvelope);
      console.error("[DEBUG] Total logs captured:", allLogs.length);
      console.error("[DEBUG] Logs containing 'crypto':", allLogs.filter(l => l.includes("crypto")));
      console.error("[DEBUG] Security handler logs:", allLogs.filter(l => l.includes("envelope_security_handler")));
      console.error("[DEBUG] First 5 logs:", allLogs.slice(0, 5));
      console.error("[DEBUG] Captured crypto_level logs:", capturedLogs);

      // Wait a bit for encryption processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      logSpy.mockRestore();

      // Verify that channel encryption was applied to the Data frame
      expect(encryptionApplied).toBe(true);
    } finally {
      basicConfig({ level: LogLevel.ERROR });

      if (child) {
        await child.stop();
        await new Promise((resolve) => setTimeout(resolve, 1200));
      }
      if (parent) {
        await parent.stop();
      }
      if (jwksServer) {
        await new Promise<void>((resolve) =>
          jwksServer!.close(() => resolve()),
        );
      }
    }
  });

  // NOTE: Sealed encryption requires recipient's public encryption key to be available.
  // Currently, KeyAnnounce frames exchange keys but sealed encryption to arbitrary
  // addresses (like __sys__@/path) requires additional key discovery mechanism.
  // This test demonstrates the configuration but encryption is currently skipped due to missing keys.
  test("Step 6: Enable sealed encryption (strict-overlay with X.509) - REQUIRES CA SERVICE", async () => {
    // NOTE: This test depends on Step 4 working, which requires CA service infrastructure.
    // Sealed encryption uses asymmetric encryption (X25519) for end-to-end encryption.
    const sentinelFactory = new SentinelFactory();
    const nodeFactory = new NodeFactory();

    let parent: Sentinel | null = null;
    let child: FameNode | null = null;
    let jwksServer: http.Server | null = null;

    try {
      const issuer = "https://step6.integration";
      const sentinelId = "step6-sentinel";
      const childId = "step6-client";
      const caCredentials = suiteCaCredentials;
      if (!caCredentials) {
        throw new Error("Test CA credentials were not initialized");
      }

      const { publicKey, privateKey } = await generateKeyPair("RS256");
      const jwk = await exportJWK(publicKey);
      jwk.kid = jwk.kid ?? "step6-key";
      const jwksBody = JSON.stringify({ keys: [jwk] });

      jwksServer = http.createServer((req, res) => {
        if (req.url === "/keys") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(jwksBody);
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        jwksServer!.listen(0, "127.0.0.1", resolve);
      });
      const address = jwksServer.address() as AddressInfo;
      const jwksUrl = `http://127.0.0.1:${address.port}/keys`;

      const sentinelCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/sentinel`,
        audience: `${sentinelId}.step6`,
        ttlSec: 600,
      });

      parent = await sentinelFactory.create({
        type: "Sentinel",
        id: sentinelId,
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "sealed", // ENABLE SEALED ENCRYPTION
          FAME_SHOW_ENVELOPES: "true",
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // DefaultCertificateManager should auto-activate for X.509
          cryptoProvider: sentinelCryptoProvider,
          crypto_provider: sentinelCryptoProvider,
        },
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
      await waitForCondition(() => Boolean(serverListener?.baseUrl));
      const baseUrl = serverListener!.baseUrl!;
      const wsBaseUrl = baseUrl.startsWith("https://")
        ? baseUrl.replace("https://", "wss://")
        : baseUrl.replace("http://", "ws://");
      const downstreamAttachUrl = `${wsBaseUrl}${serverListener!.attachPrefix}/ws/downstream`;

      const attachToken = await new SignJWT({
        scope: "node.connect",
        capabilities: ["node.connect"],
        accepted_logicals: ["svc"],
      })
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuer)
        .setAudience([parent.physicalPath ?? sentinelId, sentinelId])
        .setSubject(childId)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

      const childCryptoProvider = await DefaultCryptoProvider.create({
        issuer: `${issuer}/node`,
        audience: `${childId}.step6`,
        ttlSec: 600,
      });

      child = await nodeFactory.create({
        type: "Node",
        id: childId,
        hasParent: true,
        requestedLogicals: ["svc"],
        envContext: {
          FAME_JWT_TRUSTED_ISSUER: issuer,
          FAME_JWKS_URL: jwksUrl,
          FAME_DEFAULT_ENCRYPTION_LEVEL: "sealed",
          FAME_CA_SERVICE_URL: caCredentials.caServiceUrl,
        },
        security: {
          type: "SecurityProfile",
          profile: "strict-overlay", // X.509 certificate signing
          cryptoProvider: childCryptoProvider,
          crypto_provider: childCryptoProvider,
          // Runtime auto-creates certificate manager for x509-chain signing
        },
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
              auth: {
                type: "BearerTokenHeaderAuth",
                tokenProvider: {
                  type: "StaticTokenProvider",
                  token: attachToken,
                },
              },
            },
          ],
          ttlSec: 60,
        },
      });

      await child.start();
      await waitForCondition(() => child?.handshakeCompleted === true);

      const routeManager = (parent as unknown as { routeManager: RouteManager })
        .routeManager;
      await waitForCondition(() =>
        routeManager.downstreamRoutes.has(child!.id),
      );

      expect(child?.physicalPath).toMatch(/^\//);

      // Send a test message to verify sealed encryption is actually enabled
      const testData = {
        test: "sealed-encryption-verification",
        timestamp: Date.now(),
      };
      const testEnvelope = child.envelopeFactory.createEnvelope({
        frame: {
          type: "Data",
          codec: "json",
          payload: testData,
        },
        to: formatAddress("__sys__", parent.physicalPath!), // Send to parent's system inbox
      });

      // Track encryption by checking security handler logs
      let encryptionApplied = false;
      basicConfig({ level: LogLevel.DEBUG });
      const logSpy = jest
        .spyOn(console, "log")
        .mockImplementation((message) => {
          if (typeof message === "string") {
            // Check that sealed encryption was decided
            if (
              message.includes("outbound_crypto_level_decided") &&
              message.includes("crypto_level=sealed")
            ) {
              encryptionApplied = true;
            }
            // Check for encryption being skipped (should NOT happen)
            if (message.includes("envelope_encryption_skipped")) {
              encryptionApplied = false;
            }
          }
        });

      await child.send(testEnvelope);

      // Wait a bit for encryption processing
      await new Promise((resolve) => setTimeout(resolve, 100));

      logSpy.mockRestore();

      // Verify that sealed encryption was applied to the Data frame
      expect(encryptionApplied).toBe(true);
    } finally {
      basicConfig({ level: LogLevel.ERROR });

      if (child) {
        await child.stop();
      }
      if (parent) {
        await parent.stop();
      }
      if (jwksServer) {
        await new Promise<void>((resolve) =>
          jwksServer!.close(() => resolve()),
        );
      }
      // Wait for WebSocket receive-loop to fully shut down (has 1s join timeout)
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
  });
});
