/**
 * Factory pattern for creating CA service instances.
 *
 * Provides a unified way to create CAService implementations from configuration.
 */

import type { CreateResourceOptions, ResourceConfig } from "@naylence/factory";
import {
  AbstractResourceFactory,
  createDefaultResource,
  createResource,
} from "@naylence/factory";
import type { CAService } from "./ca-types.js";

/**
 * Configuration for CAService instances.
 */
export interface CAServiceConfig extends ResourceConfig {
  type: string;
}

/**
 * Factory for creating CAService instances.
 *
 * Supports multiple CAService implementations through the factory pattern.
 */
export abstract class CAServiceFactory<
  C extends CAServiceConfig = CAServiceConfig,
> extends AbstractResourceFactory<CAService, C> {
  /**
   * Create a CAService instance from configuration.
   *
   * @param config - Optional CAService configuration or dictionary
   * @param options - Additional creation options
   * @returns Configured CAService instance
   */
  static async createCAService(
    config?: CAServiceConfig | Record<string, unknown>,
    options?: CreateResourceOptions,
  ): Promise<CAService> {
    if (!config) {
      // Use default CA service
      const service = await createDefaultResource(
        "CAServiceFactory",
        config,
        options,
      );
      if (!service) {
        throw new Error("No default CA service factory registered");
      }
      return service as CAService;
    }

    if (typeof config === "object" && !("type" in config)) {
      // No type specified, use default
      const service = await createDefaultResource(
        "CAServiceFactory",
        config,
        options,
      );
      if (!service) {
        throw new Error("No default CA service factory registered");
      }
      return service as CAService;
    }

    // Create from specific type
    const configObj =
      config instanceof Object && "type" in config
        ? (config as CAServiceConfig)
        : ({ type: "CAService", ...config } as CAServiceConfig);

    const service = await createResource(
      "CAServiceFactory",
      configObj,
      options,
    );
    if (!service) {
      throw new Error(
        `Failed to create CA service of type "${configObj.type}"`,
      );
    }
    return service as CAService;
  }
}

/**
 * Base type for CA service factories.
 */
export const CA_SERVICE_FACTORY_BASE_TYPE = "CAServiceFactory";

/**
 * Factory metadata for CAServiceFactory.
 */
export const FACTORY_META = {
  factoryId: "CAServiceFactory",
  factoryType: CAServiceFactory,
  resourceType: "CAService",
  description:
    "Factory for creating Certificate Authority (CA) service instances",
};
