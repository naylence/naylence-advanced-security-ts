/**
 * Authorization-specific expression built-ins.
 */

import {
  BUILTIN_FUNCTIONS,
  getTypeName,
  type BuiltinFunction,
  type ExprValue,
  type FunctionRegistry,
} from "../../../expr/index.js";
import { BuiltinError } from "../../../expr/errors.js";

/**
 * Creates a function registry with auth helpers installed.
 */
export function createAuthFunctionRegistry(
  grantedScopes: readonly string[] = []
): FunctionRegistry {
  const scopes = grantedScopes ?? [];

  /**
   * Checks if any granted scope matches a pattern (using glob syntax).
   */
  const matchesScope = (scope: string): boolean => {
    // Exact match for now; safe and deterministic.
    return scopes.includes(scope);
  };

  const has_scope: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_scope");
    const scope = getArg(args, 0, "has_scope");
    assertString(scope, "scope", "has_scope");
    return matchesScope(scope);
  };

  const has_any_scope: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_any_scope");
    const values = getArg(args, 0, "has_any_scope");
    assertStringArray(values, "scopes", "has_any_scope");
    if (values.length === 0) {
      return false;
    }
    return values.some((scope) => matchesScope(scope));
  };

  const has_all_scopes: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_all_scopes");
    const values = getArg(args, 0, "has_all_scopes");
    assertStringArray(values, "scopes", "has_all_scopes");
    if (values.length === 0) {
      return true;
    }
    return values.every((scope) => matchesScope(scope));
  };

  return new Map<string, BuiltinFunction>([
    ...BUILTIN_FUNCTIONS,
    ["has_scope", has_scope],
    ["has_any_scope", has_any_scope],
    ["has_all_scopes", has_all_scopes],
  ]);
}

function assertString(
  value: ExprValue,
  argName: string,
  functionName: string
): asserts value is string {
  if (typeof value !== "string") {
    throw new BuiltinError(
      functionName,
      `${argName} must be a string, got ${getTypeName(value)}`
    );
  }
}

function assertStringArray(
  value: ExprValue,
  argName: string,
  functionName: string
): asserts value is readonly string[] {
  if (!Array.isArray(value)) {
    throw new BuiltinError(
      functionName,
      `${argName} must be an array of strings, got ${getTypeName(value)}`
    );
  }
  for (let i = 0; i < value.length; i++) {
    if (typeof value[i] !== "string") {
      throw new BuiltinError(
        functionName,
        `${argName}[${i}] must be a string, got ${getTypeName(value[i] as ExprValue)}`
      );
    }
  }
}

function getArg(
  args: readonly ExprValue[],
  index: number,
  functionName: string
): ExprValue {
  const value = args[index];
  if (value === undefined) {
    throw new BuiltinError(
      functionName,
      `missing argument at index ${index}`
    );
  }
  return value;
}

function assertArgCount(
  args: readonly ExprValue[],
  expected: number,
  functionName: string
): void {
  if (args.length !== expected) {
    throw new BuiltinError(
      functionName,
      `expected ${expected} argument(s), got ${args.length}`
    );
  }
}
