import type { FameEnvelope } from "@naylence/core";
import { DeliveryOriginType } from "@naylence/core";

import { AFTLoadBalancerStickinessManager } from "../aft-load-balancer-stickiness-manager.js";
import type { AFTLoadBalancerStickinessManagerConfig } from "../aft-load-balancer-stickiness-manager-factory.js";
import type { AFTVerifier } from "../aft-verifier.js";
import { StickinessMode } from "../stickiness-mode.js";

function createConfig(
  overrides: Partial<AFTLoadBalancerStickinessManagerConfig> = {},
): AFTLoadBalancerStickinessManagerConfig {
  return {
    type: "AFTLoadBalancerStickinessManager",
    enabled: true,
    clientEcho: false,
    defaultTtlSec: 60,
    cacheMax: 10,
    securityLevel: StickinessMode.SIGNED_OPTIONAL,
    maxTtlSec: 7200,
    ...overrides,
  };
}

describe("AFTLoadBalancerStickinessManager", () => {
  function createEnvelope(meta?: Record<string, unknown>): FameEnvelope {
    return {
      id: `env-${Math.random()}`,
      meta: meta ?? {},
    } as unknown as FameEnvelope;
  }

  it("stores associations and routes by AFT", async () => {
    const verification = {
      valid: true,
      sid: "sid-1",
      exp: Math.floor(Date.now() / 1000) + 60,
      trustLevel: "trusted" as const,
      scope: "node" as const,
      clientSid: "client-1",
    };

    const verifier: AFTVerifier = {
      securityLevel: StickinessMode.SIGNED_OPTIONAL,
      verify: jest.fn(async () => verification),
    };

    const manager = new AFTLoadBalancerStickinessManager(
      createConfig(),
      verifier,
    );

    const outbound = createEnvelope({ set: { aft: "token-1" } });
    outbound.sid = "sid-1";

    const echo = await manager.handleOutboundEnvelope(outbound, "replica-1");

    expect(echo).toBeNull();
    expect(verifier.verify).toHaveBeenCalledWith("token-1", "sid-1");
    expect(manager.getSidCache().get("client-1")).toBe("replica-1");

    const inbound = createEnvelope();
    inbound.aft = "token-1";

    const replicaId = manager.getStickyReplicaSegment(inbound, []);

    expect(replicaId).toBe("replica-1");
    expect(manager.getMetrics().associationsCreated).toBe(1);
  });

  it("falls back to SID cache when AFT missing", async () => {
    const verification = {
      valid: true,
      sid: "sid-42",
      exp: Math.floor(Date.now() / 1000) + 60,
      trustLevel: "trusted" as const,
      clientSid: "client-42",
    };

    const verifier: AFTVerifier = {
      securityLevel: StickinessMode.SIGNED_OPTIONAL,
      verify: jest.fn(async () => verification),
    };

    const manager = new AFTLoadBalancerStickinessManager(
      createConfig(),
      verifier,
    );

    const outbound = createEnvelope({ set: { aft: "tok-42" } });
    outbound.sid = "sid-42";
    await manager.handleOutboundEnvelope(outbound, "replica-42");

    const inbound = createEnvelope();
    inbound.sid = "client-42";

    const replicaId = manager.getStickyReplicaSegment(inbound, []);

    expect(replicaId).toBe("replica-42");
    expect(manager.getSidCache().get("client-42")).toBe("replica-42");
  });

  it("rejects low-trust associations in strict mode", async () => {
    const verification = {
      valid: true,
      sid: "sid-9",
      exp: Math.floor(Date.now() / 1000) + 60,
      trustLevel: "low-trust" as const,
    };

    const verifier: AFTVerifier = {
      securityLevel: StickinessMode.STRICT,
      verify: jest.fn(async () => verification),
    };

    const manager = new AFTLoadBalancerStickinessManager(
      createConfig({ securityLevel: StickinessMode.STRICT }),
      verifier,
    );

    const outbound = createEnvelope({ set: { aft: "tok-strict" } });
    outbound.sid = "sid-9";
    await manager.handleOutboundEnvelope(outbound, "replica-strict");

    const inbound = createEnvelope();
    inbound.aft = "tok-strict";

    const replicaId = manager.getStickyReplicaSegment(inbound, []);

    expect(replicaId).toBeNull();
  });

  it("evicts oldest association when cache exceeds max", async () => {
    const verification = {
      valid: true,
      sid: "sid",
      exp: Math.floor(Date.now() / 1000) + 60,
      trustLevel: "trusted" as const,
    };

    const verifier: AFTVerifier = {
      securityLevel: StickinessMode.SIGNED_OPTIONAL,
      verify: jest.fn(async () => verification),
    };

    const manager = new AFTLoadBalancerStickinessManager(
      createConfig({ cacheMax: 1 }),
      verifier,
    );

    const first = createEnvelope({ set: { aft: "token-a" } });
    first.sid = "sid";
    await manager.handleOutboundEnvelope(first, "replica-a");

    const second = createEnvelope({ set: { aft: "token-b" } });
    second.sid = "sid";
    await manager.handleOutboundEnvelope(second, "replica-b");

    const associations = manager.getAssociations();

    expect(Object.keys(associations)).toEqual(["token-b"]);
  });

  it("records downstream envelopes via onDeliver", async () => {
    const verification = {
      valid: true,
      sid: "sid-7",
      exp: Math.floor(Date.now() / 1000) + 60,
      trustLevel: "trusted" as const,
    };

    const verifier: AFTVerifier = {
      securityLevel: StickinessMode.SIGNED_OPTIONAL,
      verify: jest.fn(async () => verification),
    };

    const manager = new AFTLoadBalancerStickinessManager(
      createConfig(),
      verifier,
    );

    const envelope = createEnvelope({ set: { aft: "tok-7" } });
    envelope.sid = "sid-7";

    await manager.onDeliver({} as any, envelope, {
      originType: DeliveryOriginType.DOWNSTREAM,
      fromSystemId: "replica-7",
    } as any);

    expect(verifier.verify).toHaveBeenCalledWith("tok-7", "sid-7");
    expect(manager.getMetrics().associationsCreated).toBe(1);
  });
});
