/**
 * Authorization-specific expression built-ins.
 *
 * Null handling semantics:
 * - Scope predicate builtins (has_scope, has_any_scope, has_all_scopes)
 *   return `false` when passed `null` for required args.
 * - Security predicate builtins (is_signed, is_encrypted, is_encrypted_at_least)
 *   return `false` when the envelope lacks the required security posture.
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
 * Encryption level type for normalized security posture.
 */
export type EncryptionLevel = "plaintext" | "channel" | "sealed" | "unknown";

/**
 * Valid encryption levels for is_encrypted_at_least comparisons.
 */
const VALID_ENCRYPTION_LEVELS: readonly string[] = [
  "plaintext",
  "channel",
  "sealed",
];

/**
 * Encryption level ordering for comparison.
 * Higher number = stronger encryption.
 */
const ENCRYPTION_LEVEL_ORDER: Record<string, number> = {
  plaintext: 0,
  channel: 1,
  sealed: 2,
};

/**
 * Normalizes an encryption algorithm string to an EncryptionLevel.
 *
 * Mapping rules:
 * - null/undefined => "plaintext" (no encryption present)
 * - alg contains "-channel" => "channel" (e.g., "chacha20-poly1305-channel")
 * - alg contains "-sealed" => "sealed" (explicit sealed marker)
 * - alg matches ECDH-ES pattern with AEAD cipher => "sealed" (e.g., "ECDH-ES+A256GCM")
 * - otherwise => "unknown"
 *
 * Currently supported algorithms:
 * - Channel: "chacha20-poly1305-channel"
 * - Sealed: "ECDH-ES+A256GCM"
 *
 * This helper is centralized to ensure consistent mapping across TS and Python.
 */
export function normalizeEncryptionLevelFromAlg(
  alg: string | null | undefined
): EncryptionLevel {
  if (alg === null || alg === undefined) {
    return "plaintext";
  }

  const algLower = alg.toLowerCase();

  // Check for channel encryption (e.g., "chacha20-poly1305-channel")
  // Must check before other patterns since channel suffix is explicit
  if (algLower.includes("-channel")) {
    return "channel";
  }

  // Check for explicit sealed marker
  if (algLower.includes("-sealed")) {
    return "sealed";
  }

  // ECDH-ES key agreement with AEAD cipher => sealed encryption
  // Pattern: "ECDH-ES+A256GCM", "ECDH-ES+A128GCM", etc.
  if (algLower.startsWith("ecdh-es") && algLower.includes("+a")) {
    return "sealed";
  }

  return "unknown";
}

/**
 * Security metadata bindings exposed to expressions.
 * This is the shape of the `envelope.sec` binding.
 */
export interface SecurityBindings {
  sig: {
    present: boolean;
    kid: string | null;
  };
  enc: {
    present: boolean;
    alg: string | null;
    kid: string | null;
    level: EncryptionLevel;
  };
}

/**
 * Creates security bindings from an envelope's sec header.
 * Exposes only metadata, never raw values like sig.val or enc.val.
 */
export function createSecurityBindings(
  sec: { sig?: { kid?: string }; enc?: { alg?: string; kid?: string } } | undefined
): SecurityBindings {
  const sigPresent = sec?.sig !== undefined;
  const encPresent = sec?.enc !== undefined;

  return {
    sig: {
      present: sigPresent,
      kid: sec?.sig?.kid ?? null,
    },
    enc: {
      present: encPresent,
      alg: sec?.enc?.alg ?? null,
      kid: sec?.enc?.kid ?? null,
      level: encPresent
        ? normalizeEncryptionLevelFromAlg(sec?.enc?.alg ?? null)
        : "plaintext",
    },
  };
}

/**
 * Checks if a value is null.
 */
function isNull(value: ExprValue): value is null {
  return value === null;
}

/**
 * Options for creating an auth function registry.
 */
export interface AuthFunctionRegistryOptions {
  /**
   * Granted scopes for scope checking builtins.
   */
  grantedScopes?: readonly string[];

  /**
   * Security bindings for security posture builtins.
   * If not provided, is_signed returns false and encryption_level returns "plaintext".
   */
  securityBindings?: SecurityBindings;
}

/**
 * Creates a function registry with auth helpers installed.
 *
 * This registry extends the base builtins with:
 * - Scope builtins: has_scope, has_any_scope, has_all_scopes
 * - Security builtins: is_signed, encryption_level, is_encrypted, is_encrypted_at_least
 */
export function createAuthFunctionRegistry(
  grantedScopesOrOptions: readonly string[] | AuthFunctionRegistryOptions = []
): FunctionRegistry {
  // Handle both old signature (array) and new signature (options object)
  const options: AuthFunctionRegistryOptions = Array.isArray(grantedScopesOrOptions)
    ? { grantedScopes: grantedScopesOrOptions as readonly string[] }
    : grantedScopesOrOptions as AuthFunctionRegistryOptions;

  const scopes = options.grantedScopes ?? [];
  const secBindings = options.securityBindings ?? {
    sig: { present: false, kid: null },
    enc: { present: false, alg: null, kid: null, level: "plaintext" as const },
  };

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

  // ============================================================
  // Security posture builtins
  // ============================================================

  /**
   * is_signed() -> bool
   *
   * Returns true if the envelope has a signature present.
   * No arguments required.
   */
  const is_signed: BuiltinFunction = (args) => {
    assertArgCount(args, 0, "is_signed");
    return secBindings.sig.present;
  };

  /**
   * encryption_level() -> string
   *
   * Returns the normalized encryption level: "plaintext" | "channel" | "sealed" | "unknown"
   * No arguments required.
   */
  const encryption_level: BuiltinFunction = (args) => {
    assertArgCount(args, 0, "encryption_level");
    return secBindings.enc.level;
  };

  /**
   * is_encrypted() -> bool
   *
   * Returns true if the encryption level is not "plaintext".
   * This means the envelope has some form of encryption (channel, sealed, or unknown).
   * No arguments required.
   */
  const is_encrypted: BuiltinFunction = (args) => {
    assertArgCount(args, 0, "is_encrypted");
    return secBindings.enc.level !== "plaintext";
  };

  /**
   * is_encrypted_at_least(level: string) -> bool
   *
   * Returns true if the envelope's encryption level meets or exceeds the required level.
   *
   * Level ordering: plaintext < channel < sealed
   *
   * Special handling:
   * - "unknown" encryption level does NOT satisfy "channel" or "sealed" (conservative)
   * - "plaintext" is always satisfied (any envelope meets at least plaintext)
   * - null argument => false (predicate-style)
   * - invalid level string => BuiltinError
   */
  const is_encrypted_at_least: BuiltinFunction = (args) => {
    assertArgCount(args, 1, "is_encrypted_at_least");
    const requiredLevel = getArg(args, 0, "is_encrypted_at_least");

    // Null-tolerant: return false if level is null
    if (!assertStringOrNull(requiredLevel, "level", "is_encrypted_at_least")) {
      return false;
    }

    // Validate required level
    if (!VALID_ENCRYPTION_LEVELS.includes(requiredLevel)) {
      throw new BuiltinError(
        "is_encrypted_at_least",
        `level must be one of: ${VALID_ENCRYPTION_LEVELS.join(", ")}; got "${requiredLevel}"`
      );
    }

    const currentLevel = secBindings.enc.level;
    const requiredOrder = ENCRYPTION_LEVEL_ORDER[requiredLevel] ?? 0;
    const currentOrder = ENCRYPTION_LEVEL_ORDER[currentLevel];

    // If current level is "unknown", it only satisfies "plaintext"
    if (currentOrder === undefined) {
      // "unknown" is treated as NOT meeting channel/sealed requirements
      return requiredOrder === 0; // Only plaintext is satisfied by unknown
    }

    return currentOrder >= requiredOrder;
  };

  return new Map<string, BuiltinFunction>([
    ...BUILTIN_FUNCTIONS,
    // Scope builtins
    ["has_scope", has_scope],
    ["has_any_scope", has_any_scope],
    ["has_all_scopes", has_all_scopes],
    // Security posture builtins
    ["is_signed", is_signed],
    ["encryption_level", encryption_level],
    ["is_encrypted", is_encrypted],
    ["is_encrypted_at_least", is_encrypted_at_least],
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
