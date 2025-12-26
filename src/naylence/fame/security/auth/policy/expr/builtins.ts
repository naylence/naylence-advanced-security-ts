/**
 * Built-in functions for the expression language.
 *
 * All built-in functions are pure and deterministic.
 */

import { BuiltinError, EvaluationError } from "./errors.js";
import {
  checkGlobPatternLength,
  checkRegexPatternLength,
  type ExpressionLimits,
} from "./limits.js";

/**
 * Runtime value types for the expression language.
 */
export type ExprValue =
  | string
  | number
  | boolean
  | null
  | readonly ExprValue[]
  | { readonly [key: string]: ExprValue };

/**
 * Signature of a built-in function.
 */
export type BuiltinFunction = (
  args: readonly ExprValue[],
  context: BuiltinContext
) => ExprValue;

/**
 * Context passed to built-in functions.
 */
export interface BuiltinContext {
  /** Expression limits for pattern validation */
  readonly limits: ExpressionLimits;
  /** Position in source for error reporting */
  readonly position: number;
  /** Source expression for error reporting */
  readonly source: string;
  /** Granted scopes for scope helpers */
  readonly grantedScopes?: readonly string[];
}

/**
 * Gets the type name of a value for error messages.
 */
export function getTypeName(value: ExprValue): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * Asserts that a value is a string.
 */
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

/**
 * Asserts that a value is an array of strings.
 */
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

/**
 * Gets an argument by index, throwing if not present.
 */
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

/**
 * Asserts argument count.
 */
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

/**
 * Asserts argument count range.
 */
function assertArgCountRange(
  args: readonly ExprValue[],
  min: number,
  max: number,
  functionName: string
): void {
  if (args.length < min || args.length > max) {
    throw new BuiltinError(
      functionName,
      `expected ${min}-${max} argument(s), got ${args.length}`
    );
  }
}

// ============================================================
// Scope Helpers
// ============================================================

/**
 * Checks if any granted scope matches a pattern (using glob syntax).
 */
function matchesScope(
  scope: string,
  grantedScopes: readonly string[]
): boolean {
  // Simple exact match for now; advanced glob matching can be added
  // For v1, we do exact match which is safe and deterministic
  return grantedScopes.includes(scope);
}

/**
 * has_scope(scope: string) -> bool
 *
 * Returns true if the principal has the specified scope.
 */
const has_scope: BuiltinFunction = (args, context) => {
  assertArgCount(args, 1, "has_scope");
  const scope = getArg(args, 0, "has_scope");
  assertString(scope, "scope", "has_scope");

  if (!context.grantedScopes) {
    return false;
  }

  return matchesScope(scope, context.grantedScopes);
};

/**
 * has_any_scope(scopes: string[]) -> bool
 *
 * Returns true if the principal has any of the specified scopes.
 */
const has_any_scope: BuiltinFunction = (args, context) => {
  assertArgCount(args, 1, "has_any_scope");
  const scopes = getArg(args, 0, "has_any_scope");
  assertStringArray(scopes, "scopes", "has_any_scope");

  if (!context.grantedScopes || scopes.length === 0) {
    return false;
  }

  return scopes.some((scope) => matchesScope(scope, context.grantedScopes!));
};

/**
 * has_all_scopes(scopes: string[]) -> bool
 *
 * Returns true if the principal has all of the specified scopes.
 */
const has_all_scopes: BuiltinFunction = (args, context) => {
  assertArgCount(args, 1, "has_all_scopes");
  const scopes = getArg(args, 0, "has_all_scopes");
  assertStringArray(scopes, "scopes", "has_all_scopes");

  if (!context.grantedScopes) {
    return scopes.length === 0;
  }

  return scopes.every((scope) => matchesScope(scope, context.grantedScopes!));
};

// ============================================================
// String Helpers
// ============================================================

/**
 * lower(s: string) -> string
 *
 * Returns the lowercase version of the string.
 */
const lower: BuiltinFunction = (args) => {
  assertArgCount(args, 1, "lower");
  const s = getArg(args, 0, "lower");
  assertString(s, "s", "lower");
  return s.toLowerCase();
};

/**
 * upper(s: string) -> string
 *
 * Returns the uppercase version of the string.
 */
const upper: BuiltinFunction = (args) => {
  assertArgCount(args, 1, "upper");
  const s = getArg(args, 0, "upper");
  assertString(s, "s", "upper");
  return s.toUpperCase();
};

/**
 * starts_with(s: string, prefix: string) -> bool
 *
 * Returns true if the string starts with the prefix.
 */
const starts_with: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "starts_with");
  const s = getArg(args, 0, "starts_with");
  const prefix = getArg(args, 1, "starts_with");
  assertString(s, "s", "starts_with");
  assertString(prefix, "prefix", "starts_with");
  return s.startsWith(prefix);
};

/**
 * ends_with(s: string, suffix: string) -> bool
 *
 * Returns true if the string ends with the suffix.
 */
const ends_with: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "ends_with");
  const s = getArg(args, 0, "ends_with");
  const suffix = getArg(args, 1, "ends_with");
  assertString(s, "s", "ends_with");
  assertString(suffix, "suffix", "ends_with");
  return s.endsWith(suffix);
};

/**
 * contains(s: string, substring: string) -> bool
 *
 * Returns true if the string contains the substring.
 */
const contains: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "contains");
  const s = getArg(args, 0, "contains");
  const substring = getArg(args, 1, "contains");
  assertString(s, "s", "contains");
  assertString(substring, "substring", "contains");
  return s.includes(substring);
};

/**
 * split(s: string, separator: string) -> string[]
 *
 * Splits the string by the separator.
 */
const split: BuiltinFunction = (args) => {
  assertArgCountRange(args, 1, 2, "split");
  const s = getArg(args, 0, "split");
  assertString(s, "s", "split");

  const separator = args.length >= 2 ? getArg(args, 1, "split") : " ";
  assertString(separator, "separator", "split");

  return s.split(separator);
};

// ============================================================
// Collection Helpers
// ============================================================

/**
 * len(x: string | array) -> number
 *
 * Returns the length of a string or array.
 */
const len: BuiltinFunction = (args) => {
  assertArgCount(args, 1, "len");
  const x = getArg(args, 0, "len");

  if (typeof x === "string") {
    return x.length;
  }

  if (Array.isArray(x)) {
    return x.length;
  }

  throw new BuiltinError(
    "len",
    `expected string or array, got ${getTypeName(x)}`
  );
};

// ============================================================
// Pattern Helpers (BSL-only)
// ============================================================

/**
 * Escapes special regex characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Converts a glob pattern to a regex pattern.
 */
function globToRegex(glob: string): string {
  const parts: string[] = [];
  let i = 0;

  while (i < glob.length) {
    const ch = glob[i] as string;
    if (ch === "*") {
      if (glob[i + 1] === "*") {
        // `**` matches any characters
        parts.push(".*");
        i += 2;
      } else {
        // `*` matches any characters except dots
        parts.push("[^.]*");
        i += 1;
      }
    } else if (ch === "?") {
      // `?` matches a single character
      parts.push("[^.]");
      i += 1;
    } else {
      parts.push(escapeRegex(ch));
      i += 1;
    }
  }

  return parts.join("");
}

/**
 * glob_match(value: string, pattern: string) -> bool
 *
 * Returns true if the value matches the glob pattern.
 * Glob syntax: * (single segment), ** (any depth), ? (single char)
 */
const glob_match: BuiltinFunction = (args, context) => {
  assertArgCount(args, 2, "glob_match");
  const value = getArg(args, 0, "glob_match");
  const pattern = getArg(args, 1, "glob_match");
  assertString(value, "value", "glob_match");
  assertString(pattern, "pattern", "glob_match");

  // Validate pattern length
  checkGlobPatternLength(pattern, context.limits);

  // Convert glob to regex
  const regexPattern = `^${globToRegex(pattern)}$`;

  try {
    const regex = new RegExp(regexPattern);
    return regex.test(value);
  } catch {
    throw new BuiltinError(
      "glob_match",
      `invalid glob pattern: ${pattern}`
    );
  }
};

/**
 * Detects potentially catastrophic regex patterns.
 *
 * This is a best-effort heuristic check for common ReDoS patterns.
 */
function isSafeRegex(pattern: string): boolean {
  // Check for obvious catastrophic patterns:
  // - Nested quantifiers: (a+)+, (a*)*
  // - Overlapping alternation with quantifiers: (a|a)+

  // Simple heuristic: reject patterns with nested quantifiers
  const nestedQuantifiers = /([+*?]|\{\d+,?\d*\})\s*\)\s*([+*?]|\{\d+,?\d*\})/;
  if (nestedQuantifiers.test(pattern)) {
    return false;
  }

  // Reject patterns with excessive backtracking potential
  const excessiveBacktracking = /(\.\*){3,}|(\.\+){3,}/;
  if (excessiveBacktracking.test(pattern)) {
    return false;
  }

  return true;
}

/**
 * regex_match(value: string, pattern: string) -> bool
 *
 * Returns true if the value matches the regex pattern.
 * The pattern is anchored (full match).
 */
const regex_match: BuiltinFunction = (args, context) => {
  assertArgCount(args, 2, "regex_match");
  const value = getArg(args, 0, "regex_match");
  const pattern = getArg(args, 1, "regex_match");
  assertString(value, "value", "regex_match");
  assertString(pattern, "pattern", "regex_match");

  // Validate pattern length
  checkRegexPatternLength(pattern, context.limits);

  // Check for potentially unsafe patterns
  if (!isSafeRegex(pattern)) {
    throw new BuiltinError(
      "regex_match",
      `pattern may cause excessive backtracking: ${pattern}`
    );
  }

  // Anchor the pattern for full match
  const anchoredPattern = pattern.startsWith("^")
    ? pattern
    : pattern.endsWith("$")
      ? pattern
      : `^(?:${pattern})$`;

  try {
    const regex = new RegExp(anchoredPattern);
    return regex.test(value);
  } catch (error) {
    throw new BuiltinError(
      "regex_match",
      `invalid regex pattern: ${pattern} - ${error instanceof Error ? error.message : String(error)}`
    );
  }
};

// ============================================================
// Registry
// ============================================================

/**
 * Registry of all built-in functions.
 */
export const BUILTIN_FUNCTIONS: ReadonlyMap<string, BuiltinFunction> = new Map([
  // Scope helpers
  ["has_scope", has_scope],
  ["has_any_scope", has_any_scope],
  ["has_all_scopes", has_all_scopes],

  // String helpers
  ["lower", lower],
  ["upper", upper],
  ["starts_with", starts_with],
  ["ends_with", ends_with],
  ["contains", contains],
  ["split", split],

  // Collection helpers
  ["len", len],

  // Pattern helpers
  ["glob_match", glob_match],
  ["regex_match", regex_match],
]);

/**
 * Calls a built-in function by name.
 *
 * @param name - The function name
 * @param args - The function arguments
 * @param context - The evaluation context
 * @returns The function result
 * @throws BuiltinError if the function doesn't exist or fails
 */
export function callBuiltin(
  name: string,
  args: readonly ExprValue[],
  context: BuiltinContext
): ExprValue {
  const fn = BUILTIN_FUNCTIONS.get(name);
  if (!fn) {
    throw new EvaluationError(
      `Unknown function: ${name}`,
      context.position,
      context.source
    );
  }
  return fn(args, context);
}

/**
 * Checks if a name is a built-in function.
 */
export function isBuiltinFunction(name: string): boolean {
  return BUILTIN_FUNCTIONS.has(name);
}
