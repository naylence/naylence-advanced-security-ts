/**
 * Factory for creating AdvancedAuthorizationPolicy instances.
 */

import type { AuthorizationPolicy, AuthorizationPolicyDefinition } from "@naylence/runtime";
import {
  AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
  AuthorizationPolicyFactory,
  type AuthorizationPolicyConfig,
} from "@naylence/runtime";

import type { ExpressionLimits } from "../../../expr/limits.js";

/**
 * Configuration for creating an AdvancedAuthorizationPolicy via factory.
 */
export interface AdvancedAuthorizationPolicyConfig
  extends AuthorizationPolicyConfig {
  type: "AdvancedAuthorizationPolicy";

  /**
   * The policy definition to evaluate.
   */
  policyDefinition: AuthorizationPolicyDefinition;

  /**
   * Whether to log warnings for unknown fields.
   * @default true
   */
  warnOnUnknownFields?: boolean;

  /**
   * Expression limits for parsing and evaluation.
   */
  expressionLimits?: Partial<ExpressionLimits>;
}

type AdvancedAuthorizationPolicyModule =
  typeof import("./advanced-authorization-policy.js");

let modulePromise: Promise<AdvancedAuthorizationPolicyModule> | null = null;

function getModule(): Promise<AdvancedAuthorizationPolicyModule> {
  if (!modulePromise) {
    modulePromise = import("./advanced-authorization-policy.js");
  }
  return modulePromise;
}

interface NormalizedConfig {
  policyDefinition: AuthorizationPolicyDefinition;
  warnOnUnknownFields: boolean;
  expressionLimits?: Partial<ExpressionLimits>;
}

function normalizeConfig(
  config?: AdvancedAuthorizationPolicyConfig | Record<string, unknown> | null
): NormalizedConfig {
  if (!config) {
    throw new Error(
      "AdvancedAuthorizationPolicyFactory requires a configuration with a policyDefinition"
    );
  }

  const candidate = config as Record<string, unknown>;

  // Support both camelCase and snake_case for policyDefinition
  const policyDefinition = (candidate.policyDefinition ??
    candidate.policy_definition) as AuthorizationPolicyDefinition | undefined;
  if (!policyDefinition || typeof policyDefinition !== "object") {
    throw new Error(
      "AdvancedAuthorizationPolicyConfig requires a policyDefinition object"
    );
  }

  // Support both camelCase and snake_case for warnOnUnknownFields
  const warnOnUnknownFields =
    candidate.warnOnUnknownFields ?? candidate.warn_on_unknown_fields;
  if (
    warnOnUnknownFields !== undefined &&
    typeof warnOnUnknownFields !== "boolean"
  ) {
    throw new Error("warnOnUnknownFields must be a boolean");
  }

  // Support both camelCase and snake_case for expressionLimits
  const expressionLimits = (candidate.expressionLimits ??
    candidate.expression_limits) as Partial<ExpressionLimits> | undefined;

  return {
    policyDefinition,
    warnOnUnknownFields: warnOnUnknownFields ?? true,
    expressionLimits,
  };
}

/**
 * Factory metadata for registration.
 */
export const FACTORY_META = {
  base: AUTHORIZATION_POLICY_FACTORY_BASE_TYPE,
  key: "AdvancedAuthorizationPolicy",
} as const;

/**
 * Factory for creating AdvancedAuthorizationPolicy instances.
 */
export class AdvancedAuthorizationPolicyFactory extends AuthorizationPolicyFactory<AdvancedAuthorizationPolicyConfig> {
  public readonly type = "AdvancedAuthorizationPolicy";

  /**
   * Creates an AdvancedAuthorizationPolicy from the given configuration.
   *
   * @param config - Configuration with policyDefinition
   * @returns The created authorization policy
   */
  public async create(
    config?: AdvancedAuthorizationPolicyConfig | Record<string, unknown> | null
  ): Promise<AuthorizationPolicy> {
    const normalized = normalizeConfig(config);

    const { AdvancedAuthorizationPolicy } = await getModule();

    return new AdvancedAuthorizationPolicy({
      policyDefinition: normalized.policyDefinition,
      warnOnUnknownFields: normalized.warnOnUnknownFields,
      expressionLimits: normalized.expressionLimits as ExpressionLimits,
    });
  }
}

export default AdvancedAuthorizationPolicyFactory;
