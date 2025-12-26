/**
 * Authorization-specific expression built-ins.
 *
 * Null handling semantics:
 * - Scope predicate builtins (has_scope, has_any_scope, has_all_scopes)
 *   return `false` when passed `null` for required args.
 * - Wrong non-null types still raise BuiltinError to surface real bugs.
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
 * Checks if a value is null.
 */
function isNull(value: ExprValue): value is null {
  return value === null;
}

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

  /**
   * has_scope(scope: string) -> bool
   *
   * Returns true if the scope is in the granted scopes.
   * Null-tolerant: returns false if scope is null.
   */
  const has_scope: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_scope");
    const scope = getArg(args, 0, "has_scope");
    // Null-tolerant: return false if scope is null
    if (!assertStringOrNull(scope, "scope", "has_scope")) return false;
    return matchesScope(scope);
  };

  /**
   * has_any_scope(scopes: string[]) -> bool
   *
   * Returns true if any scope in the array is in the granted scopes.
   * Null-tolerant: returns false if scopes is null.
   */
  const has_any_scope: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_any_scope");
    const values = getArg(args, 0, "has_any_scope");
    // Null-tolerant: return false if scopes is null
    if (!assertStringArrayOrNull(values, "scopes", "has_any_scope")) return false;
    if (values.length === 0) {
      return false;
    }
    return values.some((scope) => matchesScope(scope));
  };

  /**
   * has_all_scopes(scopes: string[]) -> bool
   *
   * Returns true if all scopes in the array are in the granted scopes.
   * Null-tolerant: returns false if scopes is null.
   */
  const has_all_scopes: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "has_all_scopes");
    const values = getArg(args, 0, "has_all_scopes");
    // Null-tolerant: return false if scopes is null
    if (!assertStringArrayOrNull(values, "scopes", "has_all_scopes")) return false;
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

/**
 * Asserts that a non-null value is a string (for null-tolerant predicates).
 * Returns false if the value is null (indicating predicate should return false).
 * Throws BuiltinError if the value is non-null but not a string.
 */
function assertStringOrNull(
  value: ExprValue,
  argName: string,
  functionName: string
): value is string {
  if (isNull(value)) {
    return false;
  }
  if (typeof value !== "string") {
    throw new BuiltinError(
      functionName,
      `${argName} must be a string, got ${getTypeName(value)}`
    );
  }
  return true;
}

/**
 * Asserts that a non-null value is an array of strings (for null-tolerant predicates).
 * Returns false if the value is null (indicating predicate should return false).
 * Throws BuiltinError if the value is non-null but not a string array.
 */
function assertStringArrayOrNull(
  value: ExprValue,
  argName: string,
  functionName: string
): value is readonly string[] {
  if (isNull(value)) {
    return false;
  }
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
  return true;
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
