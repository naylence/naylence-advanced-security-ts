/**
 * Tests for null/undefined handling in the expression engine.
 *
 * This test suite verifies:
 * 1. Value resolution: undefined is normalized to null everywhere
 * 2. Predicate builtins are null-tolerant: return false for null args
 * 3. Wrong types still throw BuiltinError
 * 4. evaluateAsBoolean behavior with null-tolerant predicates
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluate,
  evaluateAsBoolean,
  normalizeJsValue,
  type EvaluationContext,
  type ExprValue,
} from "../index.js";

function evalExpr(
  expression: string,
  bindings: Record<string, unknown> = {}
): ExprValue {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings: bindings as Record<string, ExprValue>,
    source: expression,
  };
  const result = evaluate(ast, context);
  if (!result.success) {
    throw new Error(result.error);
  }
  return result.value;
}

function evalBoolResult(
  expression: string,
  bindings: Record<string, unknown> = {}
): { value: boolean; error?: string } {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings: bindings as Record<string, ExprValue>,
    source: expression,
  };
  return evaluateAsBoolean(ast, context);
}

describe("normalizeJsValue", () => {
  it("normalizes undefined to null", () => {
    expect(normalizeJsValue(undefined)).toBe(null);
  });

  it("normalizes null to null", () => {
    expect(normalizeJsValue(null)).toBe(null);
  });

  it("preserves booleans", () => {
    expect(normalizeJsValue(true)).toBe(true);
    expect(normalizeJsValue(false)).toBe(false);
  });

  it("preserves numbers", () => {
    expect(normalizeJsValue(42)).toBe(42);
    expect(normalizeJsValue(3.14)).toBe(3.14);
    expect(normalizeJsValue(0)).toBe(0);
    expect(normalizeJsValue(-1)).toBe(-1);
  });

  it("preserves strings", () => {
    expect(normalizeJsValue("hello")).toBe("hello");
    expect(normalizeJsValue("")).toBe("");
  });

  it("normalizes array elements", () => {
    const input = [1, undefined, "test", null];
    const expected = [1, null, "test", null];
    expect(normalizeJsValue(input)).toEqual(expected);
  });

  it("normalizes nested array elements", () => {
    const input = [[undefined, 1], [2, undefined]];
    const expected = [[null, 1], [2, null]];
    expect(normalizeJsValue(input)).toEqual(expected);
  });

  it("preserves objects (normalization on access)", () => {
    const input = { a: 1, b: undefined };
    const result = normalizeJsValue(input);
    expect(result).toBe(input); // Same reference
  });

  it("converts functions to null", () => {
    expect(normalizeJsValue(() => {})).toBe(null);
  });

  it("converts symbols to null", () => {
    expect(normalizeJsValue(Symbol("test"))).toBe(null);
  });
});

describe("Value resolution with undefined normalization", () => {
  describe("identifier binding lookup", () => {
    it("returns null for missing binding", () => {
      expect(evalExpr("unknown")).toBe(null);
    });

    it("returns value for present binding", () => {
      expect(evalExpr("x", { x: 42 })).toBe(42);
    });

    it("normalizes undefined binding value to null", () => {
      expect(evalExpr("x", { x: undefined })).toBe(null);
    });

    it("normalizes null binding value to null", () => {
      expect(evalExpr("x", { x: null })).toBe(null);
    });
  });

  describe("member access", () => {
    it("returns null for null base object", () => {
      expect(evalExpr("x.prop", { x: null })).toBe(null);
    });

    it("returns null for missing property", () => {
      expect(evalExpr("obj.missing", { obj: {} })).toBe(null);
    });

    it("normalizes undefined property value to null", () => {
      expect(evalExpr("obj.prop", { obj: { prop: undefined } })).toBe(null);
    });

    it("returns value for present property", () => {
      expect(evalExpr("obj.prop", { obj: { prop: "value" } })).toBe("value");
    });

    it("returns null for non-object base (primitive)", () => {
      expect(evalExpr("x.prop", { x: "string" })).toBe(null);
    });

    it("returns null for non-object base (array)", () => {
      expect(evalExpr("x.prop", { x: [1, 2, 3] })).toBe(null);
    });
  });

  describe("nested member access", () => {
    it("returns null for deeply nested missing property", () => {
      expect(evalExpr("a.b.c.d", { a: {} })).toBe(null);
    });

    it("returns null when intermediate is undefined", () => {
      expect(evalExpr("a.b.c", { a: { b: undefined } })).toBe(null);
    });

    it("returns null when intermediate is null", () => {
      expect(evalExpr("a.b.c", { a: { b: null } })).toBe(null);
    });

    it("returns value for deeply nested present property", () => {
      expect(evalExpr("a.b.c", { a: { b: { c: "deep" } } })).toBe("deep");
    });

    it("normalizes undefined at any level", () => {
      // claims.user.sub undefined at sub level
      const bindings = { claims: { user: { sub: undefined } } };
      expect(evalExpr("claims.user.sub", bindings)).toBe(null);
    });
  });

  describe("index access", () => {
    it("returns null for null base", () => {
      expect(evalExpr("x[0]", { x: null })).toBe(null);
    });

    it("returns null for out of bounds index", () => {
      expect(evalExpr("arr[10]", { arr: [1, 2, 3] })).toBe(null);
    });

    it("returns null for negative index", () => {
      expect(evalExpr("arr[-1]", { arr: [1, 2, 3] })).toBe(null);
    });

    it("returns value for valid array index", () => {
      expect(evalExpr("arr[1]", { arr: ["a", "b", "c"] })).toBe("b");
    });

    it("normalizes undefined array element to null", () => {
      const arr = ["a", undefined, "c"];
      expect(evalExpr("arr[1]", { arr })).toBe(null);
    });

    it("returns null for missing object key", () => {
      expect(evalExpr('obj["missing"]', { obj: {} })).toBe(null);
    });

    it("returns value for present object key", () => {
      expect(evalExpr('obj["key"]', { obj: { key: "value" } })).toBe("value");
    });

    it("normalizes undefined object value to null", () => {
      expect(evalExpr('obj["key"]', { obj: { key: undefined } })).toBe(null);
    });
  });
});

describe("Predicate builtins null tolerance", () => {
  describe("starts_with", () => {
    it("returns false when first arg is null", () => {
      expect(evalExpr('starts_with(null, "pre")')).toBe(false);
    });

    it("returns false when second arg is null", () => {
      expect(evalExpr('starts_with("hello", null)')).toBe(false);
    });

    it("returns false when both args are null", () => {
      expect(evalExpr("starts_with(null, null)")).toBe(false);
    });

    it("returns false when first arg resolves to null via missing property", () => {
      expect(evalExpr('starts_with(obj.missing, "pre")', { obj: {} })).toBe(false);
    });

    it("returns false when first arg is undefined property", () => {
      expect(evalExpr('starts_with(obj.prop, "pre")', { obj: { prop: undefined } })).toBe(false);
    });

    it("throws for wrong type (number)", () => {
      expect(() => evalExpr('starts_with(42, "pre")')).toThrow(/string/);
    });

    it("throws for wrong type (object)", () => {
      expect(() => evalExpr('starts_with(obj, "pre")', { obj: {} })).toThrow(/string/);
    });

    it("returns true for matching prefix", () => {
      expect(evalExpr('starts_with("hello", "hel")')).toBe(true);
    });

    it("returns false for non-matching prefix", () => {
      expect(evalExpr('starts_with("hello", "xyz")')).toBe(false);
    });
  });

  describe("ends_with", () => {
    it("returns false when first arg is null", () => {
      expect(evalExpr('ends_with(null, "suf")')).toBe(false);
    });

    it("returns false when second arg is null", () => {
      expect(evalExpr('ends_with("hello", null)')).toBe(false);
    });

    it("returns false when arg is undefined property", () => {
      expect(evalExpr('ends_with(obj.prop, "suf")', { obj: { prop: undefined } })).toBe(false);
    });

    it("throws for wrong type (array)", () => {
      expect(() => evalExpr('ends_with(arr, "suf")', { arr: [] })).toThrow(/string/);
    });

    it("returns true for matching suffix", () => {
      expect(evalExpr('ends_with("hello", "llo")')).toBe(true);
    });

    it("returns false for non-matching suffix", () => {
      expect(evalExpr('ends_with("hello", "xyz")')).toBe(false);
    });
  });

  describe("contains", () => {
    it("returns false when first arg is null", () => {
      expect(evalExpr('contains(null, "sub")')).toBe(false);
    });

    it("returns false when second arg is null", () => {
      expect(evalExpr('contains("hello", null)')).toBe(false);
    });

    it("returns false when arg is undefined property", () => {
      expect(evalExpr('contains(obj.prop, "sub")', { obj: { prop: undefined } })).toBe(false);
    });

    it("throws for wrong type (boolean)", () => {
      expect(() => evalExpr('contains(true, "sub")')).toThrow(/string/);
    });

    it("returns true for matching substring", () => {
      expect(evalExpr('contains("hello world", "lo wo")')).toBe(true);
    });

    it("returns false for non-matching substring", () => {
      expect(evalExpr('contains("hello", "xyz")')).toBe(false);
    });
  });

  describe("glob_match", () => {
    it("returns false when value is null", () => {
      expect(evalExpr('glob_match(null, "*.txt")')).toBe(false);
    });

    it("returns false when pattern is null", () => {
      expect(evalExpr('glob_match("file.txt", null)')).toBe(false);
    });

    it("returns false when value is undefined property", () => {
      expect(evalExpr('glob_match(obj.prop, "*.txt")', { obj: { prop: undefined } })).toBe(false);
    });

    it("throws for wrong type (number)", () => {
      expect(() => evalExpr('glob_match(123, "*.txt")')).toThrow(/string/);
    });

    it("throws for wrong pattern type (array)", () => {
      expect(() => evalExpr('glob_match("file.txt", arr)', { arr: [] })).toThrow(/string/);
    });

    it("returns true for matching glob pattern", () => {
      expect(evalExpr('glob_match("hello.world", "hello.*")')).toBe(true);
    });

    it("returns false for non-matching glob pattern", () => {
      expect(evalExpr('glob_match("hello.world", "foo.*")')).toBe(false);
    });
  });

  describe("regex_match", () => {
    it("returns false when value is null", () => {
      expect(evalExpr('regex_match(null, ".*")')).toBe(false);
    });

    it("returns false when pattern is null", () => {
      expect(evalExpr('regex_match("hello", null)')).toBe(false);
    });

    it("returns false when value is undefined property", () => {
      expect(evalExpr('regex_match(obj.prop, ".*")', { obj: { prop: undefined } })).toBe(false);
    });

    it("throws for wrong type (object)", () => {
      expect(() => evalExpr('regex_match(obj, ".*")', { obj: {} })).toThrow(/string/);
    });

    it("returns true for matching regex pattern", () => {
      expect(evalExpr('regex_match("hello123", "hello\\\\d+")')).toBe(true);
    });

    it("returns false for non-matching regex pattern", () => {
      expect(evalExpr('regex_match("hello", "world")')).toBe(false);
    });
  });
});

describe("evaluateAsBoolean behavior with null-tolerant predicates", () => {
  it("returns value: false with no error for null input to predicate", () => {
    const result = evalBoolResult('starts_with(obj.missing, "pre")', { obj: {} });
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("returns value: false with no error for undefined property input", () => {
    const result = evalBoolResult('ends_with(obj.prop, "suf")', { obj: { prop: undefined } });
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("returns value: false with error for wrong type input", () => {
    const result = evalBoolResult('contains(42, "sub")', {});
    expect(result.value).toBe(false);
    expect(result.error).toMatch(/string/);
  });

  it("returns value: true with no error for valid true result", () => {
    const result = evalBoolResult('starts_with("hello", "hel")', {});
    expect(result.value).toBe(true);
    expect(result.error).toBeUndefined();
  });

  it("returns value: false with no error for valid false result", () => {
    const result = evalBoolResult('starts_with("hello", "xyz")', {});
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("handles complex expression with null propagation", () => {
    const result = evalBoolResult(
      'starts_with(claims.sub, "node-") && ends_with(claims.email, "@example.com")',
      { claims: { sub: null, email: "user@example.com" } }
    );
    // starts_with returns false due to null, && short-circuits
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });

  it("handles missing nested property in expression", () => {
    const result = evalBoolResult(
      'contains(claims.user.name, "admin")',
      { claims: {} }
    );
    expect(result.value).toBe(false);
    expect(result.error).toBeUndefined();
  });
});

describe("Parameterized null tolerance tests", () => {
  describe.each([
    // [functionCall, bindings, expectedResult, shouldError]
    ['starts_with(null, "x")', {}, false, false],
    ['starts_with("x", null)', {}, false, false],
    ['starts_with(x, "pre")', { x: undefined }, false, false],
    ['starts_with(42, "x")', {}, false, true],
    ['ends_with(null, "x")', {}, false, false],
    ['ends_with("x", null)', {}, false, false],
    ['ends_with(x, "suf")', { x: undefined }, false, false],
    ['ends_with(obj, "x")', { obj: {} }, false, true],
    ['contains(null, "x")', {}, false, false],
    ['contains("x", null)', {}, false, false],
    ['contains(x, "sub")', { x: undefined }, false, false],
    ['contains(arr, "x")', { arr: [] }, false, true],
    ['glob_match(null, "*")', {}, false, false],
    ['glob_match("x", null)', {}, false, false],
    ['glob_match(x, "*")', { x: undefined }, false, false],
    ['glob_match(true, "*")', {}, false, true],
    ['regex_match(null, ".*")', {}, false, false],
    ['regex_match("x", null)', {}, false, false],
    ['regex_match(x, ".*")', { x: undefined }, false, false],
    ['regex_match(false, ".*")', {}, false, true],
  ])("predicate function: %s", (expr, bindings, expectedValue, shouldError) => {
    it(`returns ${expectedValue} ${shouldError ? "with error" : "without error"}`, () => {
      const result = evalBoolResult(expr, bindings);
      expect(result.value).toBe(expectedValue);
      if (shouldError) {
        expect(result.error).toBeDefined();
      } else {
        expect(result.error).toBeUndefined();
      }
    });
  });
});
