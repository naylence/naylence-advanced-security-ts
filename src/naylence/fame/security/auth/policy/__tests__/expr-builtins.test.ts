/**
 * Tests for authorization-specific expression built-ins.
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluate,
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

function evalBoolResult(
  expression: string,
  bindings: Record<string, ExprValue> = {},
  grantedScopes: string[] = []
): { value: boolean; error?: string } {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings,
    source: expression,
    functions: createAuthFunctionRegistry(grantedScopes),
  };
  return evaluateAsBoolean(ast, context);
}

function evalExpr(
  expression: string,
  bindings: Record<string, unknown> = {},
  grantedScopes: string[] = []
): ExprValue {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings: bindings as Record<string, ExprValue>,
    source: expression,
    functions: createAuthFunctionRegistry(grantedScopes),
  };
  const result = evaluate(ast, context);
  if (!result.success) {
    throw new Error(result.error);
  }
  return result.value;
}

describe("Auth expression built-ins", () => {
  describe("has_scope", () => {
    it("returns true for granted scope", () => {
      expect(evalBool('has_scope("admin")', {}, ["admin", "write"])).toBe(true);
    });

    it("returns false for missing scope", () => {
      expect(evalBool('has_scope("admin")', {}, ["read"])).toBe(false);
    });

    it("returns false for empty granted scopes", () => {
      expect(evalBool('has_scope("admin")', {}, [])).toBe(false);
    });
  });

  describe("has_any_scope", () => {
    it("returns true if any scope is granted", () => {
      expect(
        evalBool('has_any_scope(["admin", "write"])', {}, ["write"])
      ).toBe(true);
    });

    it("returns false if no scope is granted", () => {
      expect(
        evalBool('has_any_scope(["admin", "write"])', {}, ["read"])
      ).toBe(false);
    });

    it("returns false for empty input array", () => {
      expect(evalBool("has_any_scope([])", {}, ["admin"])).toBe(false);
    });
  });

  describe("has_all_scopes", () => {
    it("returns true if all scopes are granted", () => {
      expect(
        evalBool('has_all_scopes(["read", "write"])', {}, [
          "read",
          "write",
          "admin",
        ])
      ).toBe(true);
    });

    it("returns false if not all scopes are granted", () => {
      expect(
        evalBool('has_all_scopes(["read", "write"])', {}, ["read"])
      ).toBe(false);
    });

    it("returns true for empty input array (vacuously true)", () => {
      expect(evalBool("has_all_scopes([])", {}, ["admin"])).toBe(true);
    });
  });
});

describe("Auth built-ins null tolerance", () => {
  describe("has_scope with null", () => {
    it("returns false when scope arg is null", () => {
      expect(evalExpr("has_scope(null)", {}, ["admin"])).toBe(false);
    });

    it("returns false when scope arg is missing property", () => {
      expect(evalExpr("has_scope(obj.missing)", { obj: {} }, ["admin"])).toBe(false);
    });

    it("returns false when scope arg is undefined property", () => {
      expect(evalExpr("has_scope(obj.scope)", { obj: { scope: undefined } }, ["admin"])).toBe(false);
    });

    it("throws for wrong type (number)", () => {
      expect(() => evalExpr("has_scope(42)", {}, [])).toThrow(/string/);
    });

    it("throws for wrong type (array)", () => {
      expect(() => evalExpr("has_scope(arr)", { arr: [] }, [])).toThrow(/string/);
    });
  });

  describe("has_any_scope with null", () => {
    it("returns false when scopes arg is null", () => {
      expect(evalExpr("has_any_scope(null)", {}, ["admin"])).toBe(false);
    });

    it("returns false when scopes arg is missing property", () => {
      expect(evalExpr("has_any_scope(obj.missing)", { obj: {} }, ["admin"])).toBe(false);
    });

    it("returns false when scopes arg is undefined property", () => {
      expect(evalExpr("has_any_scope(obj.scopes)", { obj: { scopes: undefined } }, ["admin"])).toBe(false);
    });

    it("throws for wrong type (string)", () => {
      expect(() => evalExpr('has_any_scope("admin")', {}, [])).toThrow(/array/);
    });

    it("throws for wrong type (number)", () => {
      expect(() => evalExpr("has_any_scope(123)", {}, [])).toThrow(/array/);
    });
  });

  describe("has_all_scopes with null", () => {
    it("returns false when scopes arg is null", () => {
      expect(evalExpr("has_all_scopes(null)", {}, ["admin"])).toBe(false);
    });

    it("returns false when scopes arg is missing property", () => {
      expect(evalExpr("has_all_scopes(obj.missing)", { obj: {} }, ["admin"])).toBe(false);
    });

    it("returns false when scopes arg is undefined property", () => {
      expect(evalExpr("has_all_scopes(obj.scopes)", { obj: { scopes: undefined } }, ["admin"])).toBe(false);
    });

    it("throws for wrong type (object)", () => {
      expect(() => evalExpr("has_all_scopes(obj)", { obj: {} }, [])).toThrow(/array/);
    });

    it("throws for array containing non-strings", () => {
      expect(() => evalExpr("has_all_scopes(arr)", { arr: ["valid", 123] }, [])).toThrow(/string/);
    });
  });
});

describe("Auth built-ins evaluateAsBoolean behavior", () => {
  it("returns value: false with no error for null scope", () => {
    const result = evalBoolResult("has_scope(null)", {}, ["admin"]);
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("returns value: false with no error for null scopes array", () => {
    const result = evalBoolResult("has_any_scope(null)", {}, ["admin"]);
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("returns value: false with error for wrong type", () => {
    const result = evalBoolResult("has_scope(42)", {}, []);
    expect(result.value).toBe(false);
    expect(result.error).toMatch(/string/);
  });

  it("returns value: true with no error for valid scope match", () => {
    const result = evalBoolResult('has_scope("admin")', {}, ["admin"]);
    expect(result.value).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("handles complex expression with null scope propagation", () => {
    const result = evalBoolResult(
      'has_scope(claims.requiredScope) && has_any_scope(["admin"])',
      { claims: { requiredScope: null } },
      ["admin"]
    );
    // has_scope returns false due to null, && short-circuits
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });
});

describe("Parameterized auth builtin null tolerance tests", () => {
  describe.each([
    // [functionCall, bindings, grantedScopes, expectedResult, shouldError]
    ["has_scope(null)", {}, ["admin"], false, false],
    ["has_scope(x)", { x: undefined }, ["admin"], false, false],
    ["has_scope(x.y)", { x: {} }, ["admin"], false, false],
    ["has_scope(42)", {}, [], false, true],
    ['has_scope("admin")', {}, ["admin"], true, false],
    ['has_scope("admin")', {}, ["read"], false, false],
    ["has_any_scope(null)", {}, ["admin"], false, false],
    ["has_any_scope(x)", { x: undefined }, ["admin"], false, false],
    ['has_any_scope("str")', {}, [], false, true],
    ['has_any_scope(["admin"])', {}, ["admin"], true, false],
    ['has_any_scope(["admin"])', {}, ["read"], false, false],
    ["has_all_scopes(null)", {}, ["admin"], false, false],
    ["has_all_scopes(x)", { x: undefined }, ["admin"], false, false],
    ["has_all_scopes(123)", {}, [], false, true],
    ['has_all_scopes(["a", "b"])', {}, ["a", "b", "c"], true, false],
    ['has_all_scopes(["a", "b"])', {}, ["a"], false, false],
  ])("auth predicate: %s", (expr, bindings, scopes, expectedValue, shouldError) => {
    it(`returns ${expectedValue} ${shouldError ? "with error" : "without error"}`, () => {
      const result = evalBoolResult(expr, bindings as Record<string, ExprValue>, scopes);
      expect(result.value).toBe(expectedValue);
      if (shouldError) {
        expect(result.error).toBeDefined();
      } else {
        expect(result.error).toBeUndefined();
      }
    });
  });
});
