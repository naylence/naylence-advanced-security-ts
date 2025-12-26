/**
 * Tests for generic built-in functions (exists, coalesce, trim).
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluate,
  evaluateAsBoolean,
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

function evalBool(
  expression: string,
  bindings: Record<string, unknown> = {}
): boolean {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings: bindings as Record<string, ExprValue>,
    source: expression,
  };
  const result = evaluateAsBoolean(ast, context);
  if (result.error) {
    throw new Error(result.error);
  }
  return result.value;
}

describe("exists builtin", () => {
  describe("basic behavior", () => {
    it("returns false for null", () => {
      expect(evalExpr("exists(null)")).toBe(false);
    });

    it("returns true for string", () => {
      expect(evalExpr('exists("x")')).toBe(true);
    });

    it("returns true for empty string", () => {
      expect(evalExpr('exists("")')).toBe(true);
    });

    it("returns true for number zero", () => {
      expect(evalExpr("exists(0)")).toBe(true);
    });

    it("returns true for positive number", () => {
      expect(evalExpr("exists(42)")).toBe(true);
    });

    it("returns true for boolean false", () => {
      expect(evalExpr("exists(false)")).toBe(true);
    });

    it("returns true for boolean true", () => {
      expect(evalExpr("exists(true)")).toBe(true);
    });

    it("returns true for empty array", () => {
      expect(evalExpr("exists(arr)", { arr: [] })).toBe(true);
    });

    it("returns true for non-empty array", () => {
      expect(evalExpr("exists(arr)", { arr: [1, 2, 3] })).toBe(true);
    });

    it("returns true for empty object", () => {
      expect(evalExpr("exists(obj)", { obj: {} })).toBe(true);
    });

    it("returns true for non-empty object", () => {
      expect(evalExpr("exists(obj)", { obj: { a: 1 } })).toBe(true);
    });
  });

  describe("with missing bindings", () => {
    it("returns false for missing binding", () => {
      expect(evalExpr("exists(missing_binding)", {})).toBe(false);
    });

    it("returns false for missing property", () => {
      expect(evalExpr("exists(obj.missing)", { obj: {} })).toBe(false);
    });

    it("returns false for nested missing property", () => {
      expect(evalExpr("exists(claims.user.sub)", { claims: {} })).toBe(false);
    });

    it("returns false for undefined property", () => {
      expect(evalExpr("exists(obj.prop)", { obj: { prop: undefined } })).toBe(false);
    });

    it("returns true for present property", () => {
      expect(evalExpr("exists(obj.prop)", { obj: { prop: "value" } })).toBe(true);
    });
  });

  describe("argument validation", () => {
    it("throws for zero arguments", () => {
      expect(() => evalExpr("exists()")).toThrow(/expected 1 argument/);
    });

    it("throws for two arguments", () => {
      expect(() => evalExpr("exists(1, 2)")).toThrow(/expected 1 argument/);
    });
  });
});

describe("coalesce builtin", () => {
  describe("basic behavior", () => {
    it("returns second arg when first is null", () => {
      expect(evalExpr('coalesce(null, "b")')).toBe("b");
    });

    it("returns first arg when first is not null", () => {
      expect(evalExpr('coalesce("a", "b")')).toBe("a");
    });

    it("returns first arg when it is zero", () => {
      expect(evalExpr("coalesce(0, 1)")).toBe(0);
    });

    it("returns first arg when it is false", () => {
      expect(evalExpr("coalesce(false, true)")).toBe(false);
    });

    it("returns first arg when it is empty string", () => {
      expect(evalExpr('coalesce("", "default")')).toBe("");
    });

    it("returns first arg when it is empty array", () => {
      const result = evalExpr("coalesce(a, b)", { a: [], b: [1] });
      expect(result).toEqual([]);
    });

    it("returns first arg when it is empty object", () => {
      const result = evalExpr("coalesce(a, b)", { a: {}, b: { x: 1 } });
      expect(result).toEqual({});
    });

    it("returns second arg when both are null", () => {
      expect(evalExpr("coalesce(null, null)")).toBe(null);
    });

    it("returns non-null second arg when first is null", () => {
      expect(evalExpr("coalesce(null, 42)")).toBe(42);
    });
  });

  describe("with missing bindings", () => {
    it("returns second arg when first is missing binding", () => {
      expect(evalExpr('coalesce(missing, "default")', {})).toBe("default");
    });

    it("returns second arg when first is missing property", () => {
      expect(evalExpr('coalesce(obj.missing, "default")', { obj: {} })).toBe("default");
    });

    it("returns second arg when first is undefined property", () => {
      expect(evalExpr('coalesce(obj.prop, "default")', { obj: { prop: undefined } })).toBe("default");
    });

    it("returns first arg when present", () => {
      expect(evalExpr('coalesce(obj.prop, "default")', { obj: { prop: "value" } })).toBe("value");
    });
  });

  describe("argument validation", () => {
    it("throws for zero arguments", () => {
      expect(() => evalExpr("coalesce()")).toThrow(/expected 2 argument/);
    });

    it("throws for one argument", () => {
      expect(() => evalExpr("coalesce(1)")).toThrow(/expected 2 argument/);
    });

    it("throws for three arguments", () => {
      expect(() => evalExpr("coalesce(1, 2, 3)")).toThrow(/expected 2 argument/);
    });
  });
});

describe("trim builtin", () => {
  describe("basic behavior", () => {
    it("trims whitespace from both ends", () => {
      expect(evalExpr('trim("  hi  ")')).toBe("hi");
    });

    it("preserves empty string", () => {
      expect(evalExpr('trim("")')).toBe("");
    });

    it("returns empty string for null", () => {
      expect(evalExpr("trim(null)")).toBe("");
    });

    it("trims string with only whitespace", () => {
      expect(evalExpr('trim("   ")')).toBe("");
    });

    it("trims leading whitespace", () => {
      expect(evalExpr('trim("  hello")')).toBe("hello");
    });

    it("trims trailing whitespace", () => {
      expect(evalExpr('trim("hello  ")')).toBe("hello");
    });

    it("preserves internal whitespace", () => {
      expect(evalExpr('trim("  hello world  ")')).toBe("hello world");
    });

    it("trims tabs and newlines", () => {
      expect(evalExpr('trim("\\t\\nhello\\n\\t")')).toBe("hello");
    });

    it("handles string with no whitespace", () => {
      expect(evalExpr('trim("hello")')).toBe("hello");
    });
  });

  describe("with missing bindings", () => {
    it("returns empty string for missing binding", () => {
      expect(evalExpr("trim(missing)", {})).toBe("");
    });

    it("returns empty string for missing property", () => {
      expect(evalExpr("trim(obj.missing)", { obj: {} })).toBe("");
    });

    it("returns empty string for undefined property", () => {
      expect(evalExpr("trim(obj.prop)", { obj: { prop: undefined } })).toBe("");
    });

    it("trims present property", () => {
      expect(evalExpr("trim(obj.prop)", { obj: { prop: "  value  " } })).toBe("value");
    });
  });

  describe("type validation", () => {
    it("throws for number", () => {
      expect(() => evalExpr("trim(123)")).toThrow(/must be a string/);
    });

    it("throws for boolean", () => {
      expect(() => evalExpr("trim(true)")).toThrow(/must be a string/);
    });

    it("throws for array", () => {
      expect(() => evalExpr("trim(arr)", { arr: [] })).toThrow(/must be a string/);
    });

    it("throws for object", () => {
      expect(() => evalExpr("trim(obj)", { obj: {} })).toThrow(/must be a string/);
    });
  });

  describe("argument validation", () => {
    it("throws for zero arguments", () => {
      expect(() => evalExpr("trim()")).toThrow(/expected 1 argument/);
    });

    it("throws for two arguments", () => {
      expect(() => evalExpr('trim("a", "b")')).toThrow(/expected 1 argument/);
    });
  });
});

describe("Integration tests", () => {
  describe("exists with other predicates", () => {
    it("exists + starts_with with missing binding returns false", () => {
      const result = evalBool(
        'exists(claims.sub) && starts_with(claims.sub, "node-")',
        { claims: {} }
      );
      expect(result).toBe(false);
    });

    it("exists + starts_with with null returns false", () => {
      const result = evalBool(
        'exists(claims.sub) && starts_with(claims.sub, "node-")',
        { claims: { sub: null } }
      );
      expect(result).toBe(false);
    });

    it("exists + starts_with with present value returns true", () => {
      const result = evalBool(
        'exists(claims.sub) && starts_with(claims.sub, "node-")',
        { claims: { sub: "node-123" } }
      );
      expect(result).toBe(true);
    });

    it("exists + starts_with with non-matching value returns false", () => {
      const result = evalBool(
        'exists(claims.sub) && starts_with(claims.sub, "node-")',
        { claims: { sub: "user-123" } }
      );
      expect(result).toBe(false);
    });
  });

  describe("coalesce with trim and starts_with", () => {
    it("handles missing property with default", () => {
      const result = evalBool(
        'starts_with(trim(coalesce(claims.sub, "")), "node-")',
        { claims: {} }
      );
      expect(result).toBe(false);
    });

    it("handles null property with default", () => {
      const result = evalBool(
        'starts_with(trim(coalesce(claims.sub, "")), "node-")',
        { claims: { sub: null } }
      );
      expect(result).toBe(false);
    });

    it("handles present property with whitespace", () => {
      const result = evalBool(
        'starts_with(trim(coalesce(claims.sub, "")), "node-")',
        { claims: { sub: "  node-123  " } }
      );
      expect(result).toBe(true);
    });

    it("handles present property without match", () => {
      const result = evalBool(
        'starts_with(trim(coalesce(claims.sub, "")), "node-")',
        { claims: { sub: "user-123" } }
      );
      expect(result).toBe(false);
    });

    it("trims default value too", () => {
      const result = evalBool(
        'starts_with(trim(coalesce(claims.sub, "  default  ")), "def")',
        { claims: {} }
      );
      expect(result).toBe(true);
    });
  });

  describe("coalesce chaining", () => {
    it("can chain coalesce with exists check", () => {
      const result = evalBool(
        'exists(coalesce(claims.primary, claims.fallback))',
        { claims: { fallback: "value" } }
      );
      expect(result).toBe(true);
    });

    it("returns false when both coalesce args are null", () => {
      const result = evalBool(
        'exists(coalesce(claims.primary, claims.fallback))',
        { claims: { primary: null, fallback: null } }
      );
      expect(result).toBe(false);
    });
  });

  describe("trim with coalesce for safe string operations", () => {
    it("safely trims potentially missing string", () => {
      expect(evalExpr('trim(coalesce(obj.str, ""))', { obj: {} })).toBe("");
    });

    it("trims existing string", () => {
      expect(evalExpr('trim(coalesce(obj.str, ""))', { obj: { str: "  value  " } })).toBe("value");
    });

    it("uses default when value is null", () => {
      expect(evalExpr('trim(coalesce(obj.str, "default"))', { obj: { str: null } })).toBe("default");
    });
  });

  describe("complex compositions", () => {
    it("exists guards against null in complex expression", () => {
      const result = evalExpr(
        'exists(claims.email) ? contains(claims.email, "@") : false',
        { claims: {} }
      );
      expect(result).toBe(false);
    });

    it("coalesce provides safe defaults in expressions", () => {
      const result = evalExpr(
        'len(coalesce(claims.name, ""))',
        { claims: {} }
      );
      expect(result).toBe(0);
    });

    it("trim normalizes user input in expressions", () => {
      const result = evalExpr(
        'len(trim(coalesce(claims.name, "")))',
        { claims: { name: "   " } }
      );
      expect(result).toBe(0);
    });
  });
});

describe("Parameterized tests", () => {
  describe.each([
    // [expr, bindings, expected]
    ["exists(null)", {}, false],
    ['exists("x")', {}, true],
    ["exists(0)", {}, true],
    ["exists(false)", {}, true],
    ["exists(x)", {}, false],
    ["exists(x)", { x: null }, false],
    ["exists(x)", { x: "" }, true],
    ["exists(x)", { x: 0 }, true],
  ])("exists: %s", (expr, bindings, expected) => {
    it(`evaluates to ${expected}`, () => {
      expect(evalExpr(expr, bindings)).toBe(expected);
    });
  });

  describe.each([
    // [expr, bindings, expected]
    ['coalesce(null, "b")', {}, "b"],
    ['coalesce("a", "b")', {}, "a"],
    ["coalesce(0, 1)", {}, 0],
    ["coalesce(false, true)", {}, false],
    ['coalesce(x, "def")', {}, "def"],
    ['coalesce(x, "def")', { x: null }, "def"],
    ['coalesce(x, "def")', { x: "val" }, "val"],
  ])("coalesce: %s", (expr, bindings, expected) => {
    it(`evaluates to ${JSON.stringify(expected)}`, () => {
      expect(evalExpr(expr, bindings)).toBe(expected);
    });
  });

  describe.each([
    // [expr, bindings, expected]
    ['trim("  hi  ")', {}, "hi"],
    ['trim("")', {}, ""],
    ["trim(null)", {}, ""],
    ['trim("   ")', {}, ""],
    ["trim(x)", {}, ""],
    ["trim(x)", { x: null }, ""],
    ["trim(x)", { x: "  val  " }, "val"],
  ])("trim: %s", (expr, bindings, expected) => {
    it(`evaluates to "${expected}"`, () => {
      expect(evalExpr(expr, bindings)).toBe(expected);
    });
  });
});
