import type { NodeHelloFrame } from "naylence-core";
import {
  type NodePlacementStrategy,
  type PlacementDecision,
  type TokenIssuer,
  type TransportProvisioner,
} from "naylence-runtime";

import { GRANT_PURPOSE_CA_SIGN } from "../../security/cert/grants.js";
import { AdvancedWelcomeService } from "../advanced-welcome-service.js";

function createHello(overrides: Partial<NodeHelloFrame> = {}): NodeHelloFrame {
  return {
    type: "NodeHello",
    systemId: overrides.systemId ?? "",
    instanceId: overrides.instanceId ?? "instance-1",
    logicals: overrides.logicals ?? ["svc.example"],
    capabilities: overrides.capabilities ?? ["compute"],
    ...overrides,
  } as NodeHelloFrame;
}

describe("AdvancedWelcomeService", () => {
  let placementStrategy: NodePlacementStrategy;
  let transportProvisioner: TransportProvisioner;
  let tokenIssuer: TokenIssuer;

  beforeEach(() => {
    placementStrategy = {
      place: jest.fn(),
    } as unknown as NodePlacementStrategy;

    transportProvisioner = {
      provision: jest.fn(),
      deprovision: jest.fn(),
    } as unknown as TransportProvisioner;

    tokenIssuer = {
      issue: jest.fn(),
    } as unknown as TokenIssuer;
  });

  it("issues node attach and CA grants when placement accepted", async () => {
    const decision: PlacementDecision = {
      accept: true,
      assignedPath: "/nodes/a1",
      targetSystemId: "parent-node",
      targetPhysicalPath: "/physical/parent",
    };
    (placementStrategy.place as jest.Mock).mockResolvedValue(decision);

    (tokenIssuer.issue as jest.Mock)
      .mockResolvedValueOnce("attach-token")
      .mockResolvedValueOnce("ca-token");

    (transportProvisioner.provision as jest.Mock).mockResolvedValue({
      connectionGrant: {
        type: "HttpConnectionGrant",
        purpose: "attach",
        url: "https://edge.example"
      },
    });

    const service = new AdvancedWelcomeService({
      placementStrategy,
      transportProvisioner,
      tokenIssuer,
      caServiceUrl: "https://ca.example",
      ttlSec: 1800,
    });

    const hello = createHello({ systemId: "" });
    const metadata = { instanceId: "instance-99" };

    const frame = await service.handleHello(hello, metadata);

    expect(placementStrategy.place).toHaveBeenCalledWith(expect.objectContaining({ systemId: expect.any(String) }));
    expect(tokenIssuer.issue).toHaveBeenNthCalledWith(1, {
      aud: decision.targetPhysicalPath,
      system_id: expect.any(String),
      parent_path: decision.targetPhysicalPath,
      assigned_path: decision.assignedPath,
      accepted_logicals: expect.anything(),
      instance_id: metadata.instanceId,
    });
    expect(tokenIssuer.issue).toHaveBeenNthCalledWith(2, {
      aud: "ca",
      system_id: expect.any(String),
      assigned_path: decision.assignedPath,
      accepted_logicals: expect.anything(),
      instance_id: metadata.instanceId,
    });

    expect((transportProvisioner.provision as jest.Mock)).toHaveBeenCalledWith(
      decision,
      expect.objectContaining({ systemId: expect.any(String) }),
      expect.objectContaining({ instanceId: metadata.instanceId }),
      "attach-token"
    );

    expect(frame.connectionGrants).toHaveLength(2);
    const caGrant = frame.connectionGrants?.[1] as Record<string, unknown>;
    expect(caGrant.purpose).toBe(GRANT_PURPOSE_CA_SIGN);
    expect(caGrant.url).toBe("https://ca.example");
    expect((caGrant.auth as Record<string, unknown>).type).toBe("BearerTokenHeaderAuth");
    expect(
      ((caGrant.auth as { tokenProvider?: { token?: string } }).tokenProvider?.token)
    ).toBe("ca-token");
  });

  it("throws when placement rejects the node", async () => {
    (placementStrategy.place as jest.Mock).mockResolvedValue({
      accept: false,
      assignedPath: "/nodes/reject",
      reason: "capacity",
    } satisfies PlacementDecision);

    const service = new AdvancedWelcomeService({
      placementStrategy,
      transportProvisioner,
      tokenIssuer,
      caServiceUrl: "https://ca.example",
    });

    await expect(service.handleHello(createHello())).rejects.toThrow("capacity");
  });

  it("still adds CA grant when no upstream system", async () => {
    const decision: PlacementDecision = {
      accept: true,
      assignedPath: "/nodes/local",
    };
    (placementStrategy.place as jest.Mock).mockResolvedValue(decision);
    (tokenIssuer.issue as jest.Mock)
      .mockResolvedValueOnce("attach-token")
      .mockResolvedValueOnce("ca-token");

    const service = new AdvancedWelcomeService({
      placementStrategy,
      transportProvisioner,
      tokenIssuer,
      caServiceUrl: "https://ca.example",
    });

    const frame = await service.handleHello(createHello());

    expect(frame.connectionGrants).toHaveLength(1);
    const [grant] = frame.connectionGrants ?? [];
    expect(grant && (grant as { purpose?: string }).purpose).toBe(GRANT_PURPOSE_CA_SIGN);
  });
});
