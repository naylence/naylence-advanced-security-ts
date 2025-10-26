import type {
  Authorizer,
  NodePlacementStrategy,
  TokenIssuer,
  TransportProvisioner,
} from "@naylence/runtime";
import {
  AdvancedWelcomeServiceFactory,
  FACTORY_META as ADVANCED_WELCOME_FACTORY_META,
} from "../advanced-welcome-service-factory.js";
import { AdvancedWelcomeService } from "../advanced-welcome-service.js";
import {
  AuthorizerFactory,
  NodePlacementStrategyFactory,
  TokenIssuerFactory,
  TransportProvisionerFactory,
} from "@naylence/runtime";

describe("AdvancedWelcomeServiceFactory", () => {
  beforeEach(() => {
    jest
      .spyOn(NodePlacementStrategyFactory, "createNodePlacementStrategy")
      .mockResolvedValue({
        place: jest.fn(),
      } as unknown as NodePlacementStrategy);
    jest
      .spyOn(TransportProvisionerFactory, "createTransportProvisioner")
      .mockResolvedValue({
        provision: jest.fn(),
        deprovision: jest.fn(),
      } as unknown as TransportProvisioner);
    jest.spyOn(TokenIssuerFactory, "createTokenIssuer").mockResolvedValue({
      issue: jest.fn(),
    } as unknown as TokenIssuer);
    jest.spyOn(AuthorizerFactory, "createAuthorizer").mockResolvedValue({
      authorize: jest.fn(),
    } as unknown as Authorizer);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("creates an advanced welcome service with normalized config", async () => {
    const factory = new AdvancedWelcomeServiceFactory();

    const service = await factory.create({
      type: ADVANCED_WELCOME_FACTORY_META.key,
      caServiceUrl: "https://ca.example",
      placement: { type: "Static" },
      transport: { type: "Mock" },
      tokenIssuer: { type: "MockIssuer" },
      authorizer: { type: "MockAuthorizer" },
      ttl_sec: 420,
    });

    expect(service).toBeInstanceOf(AdvancedWelcomeService);
    expect(
      NodePlacementStrategyFactory.createNodePlacementStrategy,
    ).toHaveBeenCalledWith({ type: "Static" }, undefined);
    expect(
      TransportProvisionerFactory.createTransportProvisioner,
    ).toHaveBeenCalledWith({ type: "Mock" }, undefined);
    expect(TokenIssuerFactory.createTokenIssuer).toHaveBeenCalled();
    expect(AuthorizerFactory.createAuthorizer).toHaveBeenCalled();
  });

  it("throws when caServiceUrl is missing", async () => {
    const factory = new AdvancedWelcomeServiceFactory();

    await expect(
      factory.create({
        type: ADVANCED_WELCOME_FACTORY_META.key,
      }),
    ).rejects.toThrow("caServiceUrl");
  });
});
