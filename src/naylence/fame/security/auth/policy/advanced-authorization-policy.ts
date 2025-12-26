/**
 * Expression-based authorization policy implementation.
 *
 * Extends the basic policy with support for `when` expression evaluation.
 * This is part of the BSL-licensed Advanced Security package.
 */

import type {
  FameDeliveryContext,
  FameEnvelope,
} from "@naylence/core";

import type {
  AuthorizationPolicy,
  AuthorizationDecision,
  AuthorizationEvaluationStep,
  AuthorizationPolicyDefinition,
  AuthorizationRuleDefinition,
  RuleAction,
  RuleActionInput,
  ScopeRequirement,
} from "@naylence/runtime";
import {
  compileGlobPattern,
  compileGlobOnlyScopeRequirement,
  KNOWN_POLICY_FIELDS,
  KNOWN_RULE_FIELDS,
  VALID_ACTIONS,
  VALID_EFFECTS,
  VALID_ORIGIN_TYPES,
  type CompiledPattern,
} from "@naylence/runtime";

/**
 * Valid frame types that can be validated through authorization.
 * 
 * These frame types reach the dispatchRoutingActionSelected hook and can be
 * subject to authorization checks. Frame types NOT in this list either:
 * - Bypass authorization entirely (e.g., AddressBindAck)
 * - Are not valid frame types in the protocol
 */
export const VALID_FRAME_TYPES = [
  "Data",
  "DeliveryAck",
  "NodeAttach",
  "NodeHello",
  "NodeWelcome",
  "NodeAttachAck",
  "AddressBind",
  "AddressUnbind",
  "CapabilityAdvertise",
  "CapabilityWithdraw",
  "NodeHeartbeat",
  "NodeHeartbeatAck",
  "CreditUpdate",
  "KeyAnnounce",
  "KeyRequest",
] as const;

import type { NodeLike } from "@naylence/runtime";
import type { AstNode } from "../../../expr/ast.js";
import { parse } from "../../../expr/parser.js";
import {
  evaluateAsBoolean,
  type EvaluationContext,
} from "../../../expr/evaluator.js";
import type { ExprValue, FunctionRegistry } from "../../../expr/builtins.js";
import type { ExpressionLimits } from "../../../expr/limits.js";
import { DEFAULT_EXPRESSION_LIMITS } from "../../../expr/limits.js";
import { createAuthFunctionRegistry } from "./expr-builtins.js";

/**
 * Logger interface for minimal logging dependency.
 */
interface Logger {
  debug(event: string, data?: Record<string, unknown>): void;
  warning(event: string, data?: Record<string, unknown>): void;
}

/**
 * Simple console logger implementation.
 */
const defaultLogger: Logger = {
  debug: () => { /* noop for production */ },
  warning: (event, data) => {
    console.warn(`[naylence.security.auth.policy.expression] ${event}`, data);
  },
};

/**
 * Compiled rule for efficient repeated evaluation.
 */
interface CompiledExpressionRule {
  /** Rule identifier */
  id: string;
  /** Optional description */
  description?: string;
  /** Effect when rule matches */
  effect: "allow" | "deny";
  /** Set of allowed actions. Contains '*' if wildcard. */
  actions: Set<RuleAction>;
  /** Set of allowed frame types (lowercase). If undefined, matches any. */
  frameTypes?: Set<string>;
  /** Set of allowed origin types (lowercase). If undefined, matches any. */
  originTypes?: Set<string>;
  /** Address matchers (any-of). If undefined, matches any address. */
  addressPatterns?: CompiledPattern[];
  /** Compiled scope matcher. If undefined, no scope check. */
  scopeMatcher?: (grantedScopes: readonly string[]) => boolean;
  /** Compiled when expression AST. If undefined, no when check. */
  whenAst?: AstNode;
  /** Original when expression source (for tracing) */
  whenSource?: string;
  /** Parse error if when expression failed to compile */
  whenParseError?: string;
}

/**
 * Extracts the target address string from the envelope.
 */
function extractAddress(envelope: FameEnvelope): string | undefined {
  const to = envelope.to;
  if (!to) {
    return undefined;
  }

  if (typeof to === "string") {
    return to;
  }

  if (typeof to === "object" && "toString" in to) {
    return to.toString();
  }

  return undefined;
}

/**
 * Extracts granted scopes from the authorization context.
 */
function extractGrantedScopes(
  context?: FameDeliveryContext
): readonly string[] {
  const authContext = context?.security?.authorization;
  if (!authContext) {
    return [];
  }

  if (Array.isArray(authContext.grantedScopes)) {
    return authContext.grantedScopes;
  }

  const claims = authContext.claims as Record<string, unknown> | undefined;
  if (claims) {
    const scopeClaim = claims.scope ?? claims.scopes ?? claims.scp;

    if (typeof scopeClaim === "string") {
      return scopeClaim.split(/\s+/).filter((s) => s.length > 0);
    }

    if (Array.isArray(scopeClaim)) {
      return scopeClaim.filter(
        (s): s is string => typeof s === "string"
      );
    }
  }

  return [];
}

/**
 * Extracts claims from the authorization context.
 */
function extractClaims(
  context?: FameDeliveryContext
): Record<string, ExprValue> {
  const authContext = context?.security?.authorization;
  if (!authContext?.claims) {
    return {};
  }
  return authContext.claims as Record<string, ExprValue>;
}

/**
 * Creates a safe envelope subset for expression bindings.
 */
function createEnvelopeBindings(
  envelope: FameEnvelope
): Record<string, ExprValue> {
  const frame = envelope.frame as Record<string, unknown> | undefined;
  const envelopeRecord = envelope as Record<string, unknown>;

  return {
    id: envelope.id as string ?? null,
    traceId: envelopeRecord.traceId as string ?? null,
    corrId: envelopeRecord.corrId as string ?? null,
    flowId: envelopeRecord.flowId as string ?? null,
    to: extractAddress(envelope) ?? null,
    frame: frame
      ? { type: (frame.type as string | null) ?? null }
      : { type: null },
  };
}

/**
 * Creates delivery context bindings for expression evaluation.
 */
function createDeliveryBindings(
  context: FameDeliveryContext | undefined,
  action: RuleAction
): Record<string, ExprValue> {
  return {
    origin_type: context?.originType ?? null,
    routing_action: action,
  };
}

/**
 * Creates node context bindings for expression evaluation.
 */
function createNodeBindings(
  node: NodeLike
): Record<string, ExprValue> {
  return {
    id: node.id,
    sid: node.sid ?? null,
    provisionalId: node.provisionalId,
    physicalPath: node.physicalPath,
    hasParent: node.hasParent,
    publicUrl: node.publicUrl ?? null,
  };
}

/**
 * Options for creating an AdvancedAuthorizationPolicy.
 */
export interface AdvancedAuthorizationPolicyOptions {
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
   * @default DEFAULT_EXPRESSION_LIMITS
   */
  expressionLimits?: ExpressionLimits;

  /**
   * Custom logger implementation.
   */
  logger?: Logger;
}

/**
 * Expression-based authorization policy that evaluates rules with `when` expressions.
 *
 * Features:
 * - All features of BasicAuthorizationPolicy
 * - Expression evaluation for `when` clauses
 * - Deterministic, side-effect-free evaluation
 * - Missing fields evaluate to null (not error)
 * - Parse/evaluation errors cause rule to not match
 */
export class AdvancedAuthorizationPolicy implements AuthorizationPolicy {
  private readonly defaultEffect: "allow" | "deny";
  private readonly compiledRules: CompiledExpressionRule[];
  private readonly expressionLimits: ExpressionLimits;
  private readonly logger: Logger;

  constructor(options: AdvancedAuthorizationPolicyOptions) {
    const {
      policyDefinition,
      warnOnUnknownFields = true,
      expressionLimits = DEFAULT_EXPRESSION_LIMITS,
      logger = defaultLogger,
    } = options;

    this.expressionLimits = expressionLimits;
    this.logger = logger;

    // Validate and extract default effect
    this.defaultEffect = this.validateDefaultEffect(
      policyDefinition.default_effect
    );

    // Warn about unknown policy fields
    if (warnOnUnknownFields) {
      this.warnUnknownPolicyFields(policyDefinition);
    }

    // Compile rules for efficient evaluation
    this.compiledRules = this.compileRules(
      policyDefinition.rules,
      warnOnUnknownFields
    );

    this.logger.debug("expression_policy_compiled", {
      defaultEffect: this.defaultEffect,
      ruleCount: this.compiledRules.length,
      rulesWithWhen: this.compiledRules.filter((r) => r.whenAst).length,
    });
  }

  /**
   * Evaluates the policy against a request.
   */
  async evaluateRequest(
    node: NodeLike,
    envelope: FameEnvelope,
    context?: FameDeliveryContext,
    action?: RuleAction
  ): Promise<AuthorizationDecision> {
    const resolvedAction: RuleAction = action ?? "*";
    const resolvedActionNormalized =
      this.normalizeActionToken(resolvedAction) ?? resolvedAction;
    const address = extractAddress(envelope);
    const grantedScopes = extractGrantedScopes(context);
    const rawFrameType = (envelope.frame as { type?: string } | undefined)
      ?.type;
    const frameTypeNormalized =
      typeof rawFrameType === "string" && rawFrameType.trim().length > 0
        ? rawFrameType.trim().toLowerCase()
        : "";
    const rawOriginType = context?.originType;
    const originTypeNormalized =
      typeof rawOriginType === "string"
        ? this.normalizeOriginTypeToken(rawOriginType) ?? undefined
        : undefined;

    // Prepare expression bindings (lazy)
    let expressionBindings: Record<string, ExprValue> | null = null;
    let functionRegistry: FunctionRegistry | null = null;

    const evaluationTrace: AuthorizationEvaluationStep[] = [];

    // Evaluate rules in order (first match wins)
    for (const rule of this.compiledRules) {
      const step: AuthorizationEvaluationStep = {
        ruleId: rule.id,
        result: false,
      };

      // Check frame type match
      if (rule.frameTypes) {
        if (!frameTypeNormalized) {
          step.expression = "frame_type: missing";
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }

        if (!rule.frameTypes.has(frameTypeNormalized)) {
          step.expression = `frame_type: ${rawFrameType ?? "unknown"} not in rule set`;
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }
      }

      // Check origin type match
      if (rule.originTypes) {
        if (originTypeNormalized === undefined) {
          step.expression = "origin_type: missing (rule requires origin)";
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }

        if (!rule.originTypes.has(originTypeNormalized)) {
          step.expression = `origin_type: ${rawOriginType ?? "unknown"} not in [${Array.from(rule.originTypes).join(", ")}]`;
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }
      }

      // Check action match
      if (!rule.actions.has("*") && !rule.actions.has(resolvedActionNormalized)) {
        step.expression = `action: ${resolvedActionNormalized} not in [${Array.from(rule.actions).join(", ")}]`;
        step.result = false;
        evaluationTrace.push(step);
        continue;
      }

      // Check address match
      if (rule.addressPatterns) {
        if (!address) {
          step.expression = "address: pattern requires address, but none provided";
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }

        const matched = rule.addressPatterns.some((p) => p.match(address));
        if (!matched) {
          const patterns = rule.addressPatterns.map((p) => p.source).join(", ");
          step.expression = `address: none of [${patterns}] matched ${address}`;
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }
      }

      // Check scope match
      if (rule.scopeMatcher) {
        if (!rule.scopeMatcher(grantedScopes)) {
          step.expression = "scope: requirement not satisfied";
          step.boundValues = { grantedScopes: [...grantedScopes] };
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }
      }

      // Check when expression
      if (rule.whenParseError) {
        // Parse error - rule does not match
        step.expression = `when: parse error - ${rule.whenParseError}`;
        step.result = false;
        evaluationTrace.push(step);
        continue;
      }

      if (rule.whenAst) {
        // Lazy initialization of expression bindings
        if (!expressionBindings) {
          expressionBindings = {
            claims: extractClaims(context),
            envelope: createEnvelopeBindings(envelope),
            delivery: createDeliveryBindings(context, resolvedAction),
            node: createNodeBindings(node),
            time: {
              now_ms: Date.now(),
              now_iso: new Date().toISOString(),
            },
          };
        }

        const functions: FunctionRegistry =
          functionRegistry ?? createAuthFunctionRegistry(grantedScopes);
        functionRegistry = functions;

        const evalContext: EvaluationContext = {
          bindings: expressionBindings,
          limits: this.expressionLimits,
          source: rule.whenSource,
          functions,
        };

        const whenResult = evaluateAsBoolean(rule.whenAst, evalContext);

        if (whenResult.error) {
          // Evaluation error - rule does not match
          step.expression = `when: evaluation error - ${whenResult.error}`;
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }

        if (!whenResult.value) {
          // Expression evaluated to false
          step.expression = `when: expression evaluated to false`;
          step.boundValues = {
            whenExpression: rule.whenSource,
          };
          step.result = false;
          evaluationTrace.push(step);
          continue;
        }

        // Expression evaluated to true
        step.expression = `when: expression evaluated to true`;
      }

      // Rule matched
      step.result = true;
      if (!step.expression) {
        step.expression = "all conditions matched";
      }
      step.boundValues = {
        action: resolvedAction,
        address,
        grantedScopes: [...grantedScopes],
        ...(rule.whenSource ? { whenExpression: rule.whenSource } : {}),
      };
      evaluationTrace.push(step);

      this.logger.debug("rule_matched", {
        ruleId: rule.id,
        effect: rule.effect,
        action: resolvedAction,
        address,
        hadWhenClause: Boolean(rule.whenAst),
      });

      return {
        effect: rule.effect,
        reason: rule.description ?? `Matched rule: ${rule.id}`,
        matchedRule: rule.id,
        evaluationTrace,
      };
    }

    // No rule matched, apply default effect
    this.logger.debug("no_rule_matched", {
      defaultEffect: this.defaultEffect,
      action: resolvedAction,
      address,
    });

    return {
      effect: this.defaultEffect,
      reason: `No rule matched, applying default effect: ${this.defaultEffect}`,
      evaluationTrace,
    };
  }

  private validateDefaultEffect(effect: unknown): "allow" | "deny" {
    if (effect === undefined || effect === null) {
      return "deny";
    }
    if (effect !== "allow" && effect !== "deny") {
      throw new Error(
        `Invalid default_effect: "${String(effect)}". Must be "allow" or "deny"`
      );
    }
    return effect;
  }

  private warnUnknownPolicyFields(
    definition: AuthorizationPolicyDefinition
  ): void {
    for (const key of Object.keys(definition)) {
      if (!KNOWN_POLICY_FIELDS.has(key)) {
        this.logger.warning("unknown_policy_field", { field: key });
      }
    }
  }

  private compileRules(
    rules: AuthorizationRuleDefinition[],
    warnOnUnknown: boolean
  ): CompiledExpressionRule[] {
    return rules.map((rule, index) => this.compileRule(rule, index, warnOnUnknown));
  }

  private compileRule(
    rule: AuthorizationRuleDefinition,
    index: number,
    warnOnUnknown: boolean
  ): CompiledExpressionRule {
    const id = rule.id ?? `rule_${index}`;

    // Validate effect
    if (!VALID_EFFECTS.includes(rule.effect)) {
      throw new Error(
        `Invalid effect in rule "${id}": "${String(rule.effect)}". Must be "allow" or "deny"`
      );
    }

    // Compile action(s)
    const actions = this.compileActions(rule.action, id);

    // Compile address patterns
    const addressPatterns = this.compileAddress(rule.address, id);

    // Compile frame type gating
    const frameTypes = this.compileFrameTypes(rule.frame_type as string | string[] | undefined, id);

    // Compile origin type gating
    const originTypes = this.compileOriginTypes(rule.origin_type, id);

    // Compile scope matcher
    let scopeMatcher: ((scopes: readonly string[]) => boolean) | undefined;
    if (rule.scope !== undefined) {
      try {
        const compiled = compileGlobOnlyScopeRequirement(
          rule.scope as ScopeRequirement,
          id
        );
        scopeMatcher = (scopes) => compiled.evaluate(scopes);
      } catch (error) {
        throw new Error(
          `Invalid scope requirement in rule "${id}": ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    // Compile when expression
    let whenAst: AstNode | undefined;
    let whenSource: string | undefined;
    let whenParseError: string | undefined;

    if (typeof rule.when === "string" && rule.when.trim().length > 0) {
      whenSource = rule.when.trim();
      try {
        whenAst = parse(whenSource, this.expressionLimits);
      } catch (error) {
        // Parse error - store for evaluation time
        whenParseError =
          error instanceof Error ? error.message : String(error);
        this.logger.warning("when_parse_error", {
          ruleId: id,
          expression: whenSource,
          error: whenParseError,
        });
      }
    }

    // Warn about unknown fields
    if (warnOnUnknown) {
      for (const key of Object.keys(rule)) {
        if (!KNOWN_RULE_FIELDS.has(key)) {
          this.logger.warning("unknown_rule_field", { ruleId: id, field: key });
        }
      }
    }

    return {
      id,
      description: rule.description,
      effect: rule.effect,
      actions,
      frameTypes,
      originTypes,
      addressPatterns,
      scopeMatcher,
      whenAst,
      whenSource,
      whenParseError,
    };
  }

  private compileActions(
    action: RuleActionInput | RuleActionInput[] | undefined,
    ruleId: string
  ): Set<RuleAction> {
    if (action === undefined) {
      return new Set(["*"]);
    }

    if (typeof action === "string") {
      const normalized = this.normalizeActionToken(action);
      if (!normalized) {
        throw new Error(
          `Invalid action in rule "${ruleId}": "${action}". Must be one of: ${VALID_ACTIONS.join(", ")}`
        );
      }
      return new Set([normalized]);
    }

    if (!Array.isArray(action)) {
      throw new Error(
        `Invalid action in rule "${ruleId}": must be a string or array of strings`
      );
    }

    if (action.length === 0) {
      throw new Error(
        `Invalid action in rule "${ruleId}": array must not be empty`
      );
    }

    const actions = new Set<RuleAction>();
    for (const a of action) {
      if (typeof a !== "string") {
        throw new Error(
          `Invalid action in rule "${ruleId}": all values must be strings`
        );
      }
      const normalized = this.normalizeActionToken(a);
      if (!normalized) {
        throw new Error(
          `Invalid action in rule "${ruleId}": "${a}". Must be one of: ${VALID_ACTIONS.join(", ")}`
        );
      }
      actions.add(normalized);
    }

    return actions;
  }

  private compileAddress(
    address: string | string[] | undefined,
    ruleId: string
  ): CompiledPattern[] | undefined {
    if (address === undefined) {
      return undefined;
    }

    const context = `address in rule "${ruleId}"`;

    if (typeof address === "string") {
      const trimmed = address.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid address in rule "${ruleId}": value must not be empty`
        );
      }
      try {
        return [compileGlobPattern(trimmed, context)];
      } catch (error) {
        throw new Error(
          `Invalid address in rule "${ruleId}": ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    if (!Array.isArray(address)) {
      throw new Error(
        `Invalid address in rule "${ruleId}": must be a string or array of strings`
      );
    }

    if (address.length === 0) {
      throw new Error(
        `Invalid address in rule "${ruleId}": array must not be empty`
      );
    }

    const patterns: CompiledPattern[] = [];
    for (const addr of address) {
      if (typeof addr !== "string") {
        throw new Error(
          `Invalid address in rule "${ruleId}": all values must be strings`
        );
      }
      const trimmed = addr.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid address in rule "${ruleId}": values must not be empty`
        );
      }
      try {
        patterns.push(compileGlobPattern(trimmed, context));
      } catch (error) {
        throw new Error(
          `Invalid address in rule "${ruleId}": ${error instanceof Error ? error.message : String(error)}`
        );
      }
    }

    return patterns;
  }

  private compileFrameTypes(
    frameType: string | string[] | undefined,
    ruleId: string
  ): Set<string> | undefined {
    if (frameType === undefined) {
      return undefined;
    }

    if (typeof frameType === "string") {
      const trimmed = frameType.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid frame_type in rule "${ruleId}": value must not be empty`
        );
      }
      if (!VALID_FRAME_TYPES.includes(trimmed as any)) {
        throw new Error(
          `Invalid frame_type in rule "${ruleId}": "${trimmed}". Must be one of: ${VALID_FRAME_TYPES.join(", ")}`
        );
      }
      // Normalize to lowercase for matching
      return new Set([trimmed.toLowerCase()]);
    }

    if (!Array.isArray(frameType)) {
      throw new Error(
        `Invalid frame_type in rule "${ruleId}": must be a string or array of strings`
      );
    }

    if (frameType.length === 0) {
      throw new Error(
        `Invalid frame_type in rule "${ruleId}": array must not be empty`
      );
    }

    const types = new Set<string>();
    for (const type of frameType) {
      if (typeof type !== "string") {
        throw new Error(
          `Invalid frame_type in rule "${ruleId}": all values must be strings`
        );
      }
      const trimmed = type.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid frame_type in rule "${ruleId}": values must not be empty`
        );
      }
      if (!VALID_FRAME_TYPES.includes(trimmed as any)) {
        throw new Error(
          `Invalid frame_type in rule "${ruleId}": "${trimmed}". Must be one of: ${VALID_FRAME_TYPES.join(", ")}`
        );
      }
      // Normalize to lowercase for matching
      types.add(trimmed.toLowerCase());
    }

    return types;
  }

  private compileOriginTypes(
    originType: string | string[] | undefined,
    ruleId: string
  ): Set<string> | undefined {
    if (originType === undefined) {
      return undefined;
    }

    if (typeof originType === "string") {
      const trimmed = originType.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid origin_type in rule "${ruleId}": value must not be empty`
        );
      }
      const normalized = this.normalizeOriginTypeToken(trimmed);
      if (!normalized) {
        throw new Error(
          `Invalid origin_type in rule "${ruleId}": "${originType}". Must be one of: ${VALID_ORIGIN_TYPES.join(", ")}`
        );
      }
      return new Set([normalized]);
    }

    if (!Array.isArray(originType)) {
      throw new Error(
        `Invalid origin_type in rule "${ruleId}": must be a string or array of strings`
      );
    }

    if (originType.length === 0) {
      throw new Error(
        `Invalid origin_type in rule "${ruleId}": array must not be empty`
      );
    }

    const originTypes = new Set<string>();
    for (const ot of originType) {
      if (typeof ot !== "string") {
        throw new Error(
          `Invalid origin_type in rule "${ruleId}": all values must be strings`
        );
      }
      const trimmed = ot.trim();
      if (!trimmed) {
        throw new Error(
          `Invalid origin_type in rule "${ruleId}": values must not be empty`
        );
      }
      const normalized = this.normalizeOriginTypeToken(trimmed);
      if (!normalized) {
        throw new Error(
          `Invalid origin_type in rule "${ruleId}": "${ot}". Must be one of: ${VALID_ORIGIN_TYPES.join(", ")}`
        );
      }
      originTypes.add(normalized);
    }

    return originTypes;
  }

  private normalizeActionToken(value: string): RuleAction | null {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    if (trimmed === "*") {
      return "*";
    }
    const normalized = trimmed.replace(/[\s_-]+/g, "").toLowerCase();
    const map: Record<string, RuleAction> = {
      connect: "Connect",
      forwardupstream: "ForwardUpstream",
      forwarddownstream: "ForwardDownstream",
      forwardpeer: "ForwardPeer",
      deliverlocal: "DeliverLocal",
    };
    return map[normalized] ?? null;
  }

  private normalizeOriginTypeToken(value: string): string | null {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    const normalized = trimmed.replace(/[\s_-]+/g, "").toLowerCase();
    const map: Record<string, string> = {
      downstream: "downstream",
      upstream: "upstream",
      peer: "peer",
      local: "local",
    };
    return map[normalized] ?? null;
  }
}
