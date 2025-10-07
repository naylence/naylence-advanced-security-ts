import { DeliveryOriginType } from "naylence-core";

import { AFTReplicaStickinessManager } from "../aft-replica-stickiness-manager.js";
import type { AFTHelper } from "../aft-helper.js";
import type { AFTSigner } from "../aft-signer.js";
import { StickinessMode } from "../stickiness-mode.js";

describe("AFTReplicaStickinessManager", () => {
  function createHelperSpy(): AFTHelper {
    const signer: AFTSigner = {
      securityLevel: StickinessMode.SIGNED_OPTIONAL,
      // eslint-disable-next-line @typescript-eslint/require-await
      async signAft() {
        throw new Error("not implemented");
      },
    };

    return {
      signer,
      nodeSid: "node-1",
      maxTtlSec: 7200,
      requestStickiness: jest.fn().mockResolvedValue(true),
      requestNodeStickiness: jest.fn(),
      requestFlowStickiness: jest.fn(),
      requestSessionStickiness: jest.fn(),
    } as unknown as AFTHelper;
  }

  function createEnvelope(): any {
    return { id: `env-${Math.random()}` };
  }

  it("offers aft stickiness with attr fallback", () => {
    const manager = new AFTReplicaStickinessManager();

    const offer = manager.offer();

    expect(offer).toEqual({ mode: "aft", supportedModes: ["aft", "attr"], version: 1 });
  });

  it("applies AFT when stickiness flag is set", async () => {
    const helper = createHelperSpy();
    const manager = new AFTReplicaStickinessManager({ aftHelper: helper });

    const envelope = createEnvelope();
    const context = {
      originType: DeliveryOriginType.LOCAL,
      fromSystemId: "replica-42",
      stickinessRequired: true,
    };

    await manager.onForwardUpstream({} as any, envelope, context as any);

    expect(helper.requestStickiness).toHaveBeenCalledTimes(1);
    expect(helper.requestStickiness).toHaveBeenCalledWith(envelope, {
      ttlSec: null,
      scope: "node",
      context,
    });
  });

  it("supports snake_case stickiness flag", async () => {
    const helper = createHelperSpy();
    const manager = new AFTReplicaStickinessManager({ aftHelper: helper });

    const envelope = createEnvelope();
    const context = {
      originType: DeliveryOriginType.LOCAL,
      fromSystemId: "replica-99",
      stickiness_required: true,
    };

    await manager.onForwardUpstream({} as any, envelope, context as any);

    expect(helper.requestStickiness).toHaveBeenCalledTimes(1);
  });

  it("skips AFT when policy disables stickiness", async () => {
    const helper = createHelperSpy();
    const manager = new AFTReplicaStickinessManager({ aftHelper: helper });

    manager.accept({ enabled: false, version: 1 });

    const envelope = createEnvelope();
    const context = {
      originType: DeliveryOriginType.LOCAL,
      stickinessRequired: true,
    };

    await manager.onForwardUpstream({} as any, envelope, context as any);

    expect(helper.requestStickiness).not.toHaveBeenCalled();
  });

  it("updates helper SID on node start", async () => {
    const helper = createHelperSpy();
    const manager = new AFTReplicaStickinessManager({ aftHelper: helper });

    await manager.onNodeStarted({ id: "node", sid: "sid-123", cryptoProvider: {} } as any);

    expect(helper.nodeSid).toBe("sid-123");
  });
});
