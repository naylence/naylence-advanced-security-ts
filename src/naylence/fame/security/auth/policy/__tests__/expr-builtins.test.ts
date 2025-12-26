/**
 * Tests for authorization-specific expression built-ins.
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluateAsBoolean,
  type EvaluationContext,
  type ExprValue,
} from "../../../../expr/index.js";
import { createAuthFunctionRegistry } from "../expr-builtins.js";

function evalBool(
  expression: string,
  bindings: Record<string, ExprValue> = {},
  grantedScopes: string[] = []
): boolean {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings,
    source: expression,
    functions: createAuthFunctionRegistry(grantedScopes),
  };
  const result = evaluateAsBoolean(ast, context);
  if (result.error) {
    throw new Error(result.error);
  }
  return result.value;
}

describe("Auth expression built-ins", () => {
  it("has_scope returns true for granted scope", () => {
    expect(evalBool('has_scope("admin")', {}, ["admin", "write"])).toBe(true);
  });

  it("has_scope returns false for missing scope", () => {
    expect(evalBool('has_scope("admin")', {}, ["read"])).toBe(false);
  });

  it("has_any_scope checks any scope", () => {
    expect(
      evalBool('has_any_scope(["admin", "write"])', {}, ["write"])
    ).toBe(true);
    expect(
      evalBool('has_any_scope(["admin", "write"])', {}, ["read"])
    ).toBe(false);
  });

  it("has_all_scopes checks all scopes", () => {
    expect(
      evalBool('has_all_scopes(["read", "write"])', {}, [
        "read",
        "write",
        "admin",
      ])
    ).toBe(true);
    expect(
      evalBool('has_all_scopes(["read", "write"])', {}, ["read"])
    ).toBe(false);
  });
});
