/**
 * Built-in functions for the expression language.
 *
 * All built-in functions are pure and deterministic.
 *
 * Null handling semantics:
 * - `undefined` is normalized to `null` throughout the expression value model.
 * - Predicate-style builtins (starts_with, ends_with, contains, glob_match,
 *   regex_match, etc.) return `false` when passed `null` for required args
 *   instead of throwing an error.
 * - Wrong non-null types still raise BuiltinError to surface real bugs.
 * - Non-predicate operations (arithmetic, comparisons) remain strict.
 */

import { BuiltinError, EvaluationError } from "./errors.js";
import { sha256 } from '@noble/hashes/sha2';
import { generateFingerprintSync } from '@naylence/core';
import {
  checkGlobPatternLength,
  checkRegexPatternLength,
  type ExpressionLimits,
} from "./limits.js";

/**
 * Runtime value types for the expression language.
 *
 * Note: `undefined` is NOT a valid ExprValue. Any JavaScript `undefined`
 * values should be normalized to `null` before entering the expression system.
 */
export type ExprValue =
  | string
  | number
  | boolean
  | null
  | readonly ExprValue[]
  | { readonly [key: string]: ExprValue };

/**
 * Normalizes a JavaScript value to an ExprValue.
 *
 * Rules:
 * - `undefined` -> `null`
 * - `null` -> `null`
 * - boolean/number/string -> returned as-is
 * - array -> elements are recursively normalized
 * - object -> returned as-is (reads will normalize on access)
 * - other types (function, symbol, etc.) -> `null`
 *
 * This ensures `undefined` never leaks into the expression value model.
 */
export function normalizeJsValue(value: unknown): ExprValue {
  if (value === undefined || value === null) {
    return null;
  }

  if (typeof value === "boolean" || typeof value === "number") {
    return value;
  }

  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((element) => normalizeJsValue(element));
  }

  if (typeof value === "object") {
    // Return the object as-is; reads will normalize on access
    return value as { readonly [key: string]: ExprValue };
  }

  // Function, symbol, bigint, etc. -> null
  return null;
}

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
}

/**
 * Function registry for built-in and injected functions.
 */
export type FunctionRegistry = ReadonlyMap<string, BuiltinFunction>;

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
 * Checks if a value is null (for null-tolerant predicates).
 */
function isNull(value: ExprValue): value is null {
  return value === null;
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
 * Null-tolerant: returns false if either argument is null.
 */
const starts_with: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "starts_with");
  const s = getArg(args, 0, "starts_with");
  const prefix = getArg(args, 1, "starts_with");
  // Null-tolerant: return false if either arg is null
  if (!assertStringOrNull(s, "s", "starts_with")) return false;
  if (!assertStringOrNull(prefix, "prefix", "starts_with")) return false;
  return s.startsWith(prefix);
};

/**
 * ends_with(s: string, suffix: string) -> bool
 *
 * Returns true if the string ends with the suffix.
 * Null-tolerant: returns false if either argument is null.
 */
const ends_with: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "ends_with");
  const s = getArg(args, 0, "ends_with");
  const suffix = getArg(args, 1, "ends_with");
  // Null-tolerant: return false if either arg is null
  if (!assertStringOrNull(s, "s", "ends_with")) return false;
  if (!assertStringOrNull(suffix, "suffix", "ends_with")) return false;
  return s.endsWith(suffix);
};

/**
 * contains(s: string, substring: string) -> bool
 *
 * Returns true if the string contains the substring.
 * Null-tolerant: returns false if either argument is null.
 */
const contains: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "contains");
  const s = getArg(args, 0, "contains");
  const substring = getArg(args, 1, "contains");
  // Null-tolerant: return false if either arg is null
  if (!assertStringOrNull(s, "s", "contains")) return false;
  if (!assertStringOrNull(substring, "substring", "contains")) return false;
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
// Generic Helpers
// ============================================================

/**
 * exists(x: any) -> bool
 *
 * Returns true if the value is not null.
 * Missing bindings and missing properties evaluate to null, so this
 * can be used to check for presence.
 */
const exists: BuiltinFunction = (args) => {
  assertArgCount(args, 1, "exists");
  const x = getArg(args, 0, "exists");
  return x !== null;
};

/**
 * coalesce(a: any, b: any) -> any
 *
 * Returns `a` if it is not null, otherwise returns `b`.
 * This is useful for providing default values.
 */
const coalesce: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "coalesce");
  const a = getArg(args, 0, "coalesce");
  const b = getArg(args, 1, "coalesce");
  return a !== null ? a : b;
};

/**
 * trim(s: string) -> string
 *
 * Trims whitespace from both ends of a string.
 * Returns an empty string if `s` is null (for convenient composition).
 * Throws BuiltinError if `s` is non-null but not a string.
 */
const trim: BuiltinFunction = (args) => {
  assertArgCount(args, 1, "trim");
  const s = getArg(args, 0, "trim");
  
  // Null-friendly: return empty string for null
  if (s === null) {
    return "";
  }
  
  // Strict type check for non-null values
  if (typeof s !== "string") {
    throw new BuiltinError(
      "trim",
      `s must be a string, got ${getTypeName(s)}`
    );
  }
  
  return s.trim();
};

/**
 * secure_hash(input_str: string, length: number) -> string
 *
 * Generates a deterministic secure hash/fingerprint of the input string.
 * Uses SHA-256 hashing to create a stable identifier of the specified length.
 * Returns base62-encoded string (alphanumeric, case-sensitive).
 * Automatically rehashes if result contains blacklisted words.
 * Returns empty string if input_str is null (for convenient composition).
 * Throws BuiltinError if input_str is non-null but not a string, or if length is invalid.
 */
const secure_hash: BuiltinFunction = (args) => {
  assertArgCount(args, 2, "secure_hash");
  const input_str = getArg(args, 0, "secure_hash");
  const length = getArg(args, 1, "secure_hash");
  
  // Null-friendly: return empty string for null input
  if (input_str === null) {
    return "";
  }
  
  // Strict type check for input_str
  if (typeof input_str !== "string") {
    throw new BuiltinError(
      "secure_hash",
      `input_str must be a string, got ${getTypeName(input_str)}`
    );
  }
  
  // Strict type check for length
  if (typeof length !== "number") {
    throw new BuiltinError(
      "secure_hash",
      `length must be a number, got ${getTypeName(length)}`
    );
  }
  
  // Validate length is a positive integer
  if (!Number.isInteger(length) || length <= 0) {
    throw new BuiltinError(
      "secure_hash",
      `length must be a positive integer, got ${length}`
    );
  }
  
  // Use generateFingerprintSync from @naylence/core
  // This provides SHA-256 hashing, base62 encoding, and profanity filtering
  return generateFingerprintSync(input_str, length, sha256);
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
 * Null-tolerant: returns false if either argument is null.
 */
const glob_match: BuiltinFunction = (args, context) => {
  assertArgCount(args, 2, "glob_match");
  const value = getArg(args, 0, "glob_match");
  const pattern = getArg(args, 1, "glob_match");
  // Null-tolerant: return false if either arg is null
  if (!assertStringOrNull(value, "value", "glob_match")) return false;
  if (!assertStringOrNull(pattern, "pattern", "glob_match")) return false;

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
 * Null-tolerant: returns false if either argument is null.
 */
const regex_match: BuiltinFunction = (args, context) => {
  assertArgCount(args, 2, "regex_match");
  const value = getArg(args, 0, "regex_match");
  const pattern = getArg(args, 1, "regex_match");
  // Null-tolerant: return false if either arg is null
  if (!assertStringOrNull(value, "value", "regex_match")) return false;
  if (!assertStringOrNull(pattern, "pattern", "regex_match")) return false;

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
export const BUILTIN_FUNCTIONS: FunctionRegistry = new Map([
  // String helpers
  ["lower", lower],
  ["upper", upper],
  ["starts_with", starts_with],
  ["ends_with", ends_with],
  ["contains", contains],
  ["split", split],
  ["trim", trim],

  // Collection helpers
  ["len", len],

  // Generic helpers
  ["exists", exists],
  ["coalesce", coalesce],
  ["secure_hash", secure_hash],

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
  context: BuiltinContext,
  functions: FunctionRegistry = BUILTIN_FUNCTIONS
): ExprValue {
  const fn = functions.get(name);
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
export function isBuiltinFunction(
  name: string,
  functions: FunctionRegistry = BUILTIN_FUNCTIONS
): boolean {
  return functions.has(name);
}
