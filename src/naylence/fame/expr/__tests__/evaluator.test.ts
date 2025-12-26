/**
 * Tests for expression evaluator.
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluate,
  evaluateAsBoolean,
  type EvaluationContext,
  type ExprValue,
  type FunctionRegistry,
} from "../index.js";

function evalExpr(
  expression: string,
  bindings: Record<string, ExprValue> = {},
  functions?: FunctionRegistry
): ExprValue {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings,
    source: expression,
    functions,
  };
  const result = evaluate(ast, context);
  if (!result.success) {
    throw new Error(result.error);
  }
  return result.value;
}

function evalBool(
  expression: string,
  bindings: Record<string, ExprValue> = {},
  functions?: FunctionRegistry
): boolean {
  const ast = parse(expression);
  const context: EvaluationContext = {
    bindings,
    source: expression,
    functions,
  };
  const result = evaluateAsBoolean(ast, context);
  if (result.error) {
    throw new Error(result.error);
  }
  return result.value;
}

describe("Evaluator", () => {
  describe("literals", () => {
    it("evaluates string literal", () => {
      expect(evalExpr('"hello"')).toBe("hello");
    });

    it("evaluates number literal", () => {
      expect(evalExpr("42")).toBe(42);
    });

    it("evaluates decimal literal", () => {
      expect(evalExpr("3.14")).toBeCloseTo(3.14);
    });

    it("evaluates true", () => {
      expect(evalExpr("true")).toBe(true);
    });

    it("evaluates false", () => {
      expect(evalExpr("false")).toBe(false);
    });

    it("evaluates null", () => {
      expect(evalExpr("null")).toBe(null);
    });

    it("evaluates empty array", () => {
      expect(evalExpr("[]")).toEqual([]);
    });

    it("evaluates array with elements", () => {
      expect(evalExpr("[1, 2, 3]")).toEqual([1, 2, 3]);
    });
  });

  describe("identifiers", () => {
    it("evaluates bound identifier", () => {
      expect(evalExpr("x", { x: 42 })).toBe(42);
    });

    it("evaluates unbound identifier as null", () => {
      expect(evalExpr("unknown")).toBe(null);
    });
  });

  describe("member access", () => {
    it("accesses object property", () => {
      expect(evalExpr("obj.prop", { obj: { prop: "value" } })).toBe("value");
    });

    it("accesses nested property", () => {
      const bindings = {
        a: { b: { c: 123 } },
      };
      expect(evalExpr("a.b.c", bindings)).toBe(123);
    });

    it("returns null for missing property", () => {
      expect(evalExpr("obj.missing", { obj: {} })).toBe(null);
    });

    it("returns null for null object", () => {
      expect(evalExpr("x.prop", { x: null })).toBe(null);
    });

    it("returns null for primitive", () => {
      expect(evalExpr("x.prop", { x: "string" })).toBe(null);
    });
  });

  describe("index access", () => {
    it("accesses array by index", () => {
      expect(evalExpr("arr[1]", { arr: ["a", "b", "c"] })).toBe("b");
    });

    it("accesses object by string key", () => {
      expect(evalExpr('obj["key"]', { obj: { key: "value" } })).toBe("value");
    });

    it("returns null for out of bounds", () => {
      expect(evalExpr("arr[10]", { arr: [1, 2, 3] })).toBe(null);
    });

    it("returns null for negative index", () => {
      expect(evalExpr("arr[-1]", { arr: [1, 2, 3] })).toBe(null);
    });

    it("returns null for missing key", () => {
      expect(evalExpr('obj["missing"]', { obj: {} })).toBe(null);
    });

    it("returns null for null object", () => {
      expect(evalExpr("x[0]", { x: null })).toBe(null);
    });
  });

  describe("unary operators", () => {
    it("negates boolean with !", () => {
      expect(evalExpr("!true")).toBe(false);
      expect(evalExpr("!false")).toBe(true);
    });

    it("negates number with -", () => {
      expect(evalExpr("-5")).toBe(-5);
      expect(evalExpr("--5")).toBe(5);
    });

    it("throws on ! with non-boolean", () => {
      expect(() => evalExpr("!5")).toThrow(/boolean/);
    });

    it("throws on - with non-number", () => {
      expect(() => evalExpr('-"str"')).toThrow(/number/);
    });
  });

  describe("arithmetic operators", () => {
    it("adds numbers", () => {
      expect(evalExpr("2 + 3")).toBe(5);
    });

    it("concatenates strings", () => {
      expect(evalExpr('"a" + "b"')).toBe("ab");
    });

    it("subtracts numbers", () => {
      expect(evalExpr("5 - 3")).toBe(2);
    });

    it("multiplies numbers", () => {
      expect(evalExpr("4 * 5")).toBe(20);
    });

    it("divides numbers", () => {
      expect(evalExpr("10 / 4")).toBe(2.5);
    });

    it("computes modulo", () => {
      expect(evalExpr("10 % 3")).toBe(1);
    });

    it("throws on division by zero", () => {
      expect(() => evalExpr("5 / 0")).toThrow(/zero/);
    });

    it("throws on modulo by zero", () => {
      expect(() => evalExpr("5 % 0")).toThrow(/zero/);
    });

    it("throws on invalid operand types", () => {
      expect(() => evalExpr('5 + "x"')).toThrow();
      expect(() => evalExpr('"a" - "b"')).toThrow();
    });
  });

  describe("comparison operators", () => {
    it("compares numbers", () => {
      expect(evalExpr("3 < 5")).toBe(true);
      expect(evalExpr("3 <= 3")).toBe(true);
      expect(evalExpr("5 > 3")).toBe(true);
      expect(evalExpr("5 >= 5")).toBe(true);
    });

    it("compares strings", () => {
      expect(evalExpr('"a" < "b"')).toBe(true);
      expect(evalExpr('"abc" > "ab"')).toBe(true);
    });

    it("throws on incompatible types", () => {
      expect(() => evalExpr('5 < "x"')).toThrow();
    });
  });

  describe("equality operators", () => {
    it("compares primitives", () => {
      expect(evalExpr("1 == 1")).toBe(true);
      expect(evalExpr("1 == 2")).toBe(false);
      expect(evalExpr('"a" == "a"')).toBe(true);
      expect(evalExpr("true == true")).toBe(true);
      expect(evalExpr("null == null")).toBe(true);
    });

    it("handles inequality", () => {
      expect(evalExpr("1 != 2")).toBe(true);
      expect(evalExpr("1 != 1")).toBe(false);
    });

    it("compares arrays deeply", () => {
      expect(evalExpr("[1, 2] == [1, 2]")).toBe(true);
      expect(evalExpr("[1, 2] == [1, 3]")).toBe(false);
    });

    it("compares objects deeply", () => {
      const bindings = {
        a: { x: 1, y: 2 },
        b: { x: 1, y: 2 },
        c: { x: 1, y: 3 },
      };
      expect(evalExpr("a == b", bindings)).toBe(true);
      expect(evalExpr("a == c", bindings)).toBe(false);
    });

    it("handles type mismatches", () => {
      expect(evalExpr("1 == true")).toBe(false);
      expect(evalExpr('"1" == 1')).toBe(false);
    });
  });

  describe("logical operators", () => {
    it("evaluates &&", () => {
      expect(evalExpr("true && true")).toBe(true);
      expect(evalExpr("true && false")).toBe(false);
      expect(evalExpr("false && true")).toBe(false);
    });

    it("evaluates ||", () => {
      expect(evalExpr("true || false")).toBe(true);
      expect(evalExpr("false || true")).toBe(true);
      expect(evalExpr("false || false")).toBe(false);
    });

    it("short-circuits &&", () => {
      // If short-circuit works, x.prop won't be evaluated
      expect(evalExpr("false && x.prop", { x: null })).toBe(false);
    });

    it("short-circuits ||", () => {
      expect(evalExpr("true || x.prop", { x: null })).toBe(true);
    });

    it("throws on non-boolean operands", () => {
      expect(() => evalExpr("1 && true")).toThrow(/boolean/);
      expect(() => evalExpr("true && 1")).toThrow(/boolean/);
      expect(() => evalExpr('"x" || false')).toThrow(/boolean/);
    });
  });

  describe("membership operators", () => {
    it("checks value in array", () => {
      expect(evalExpr('"b" in ["a", "b", "c"]')).toBe(true);
      expect(evalExpr('"x" in ["a", "b", "c"]')).toBe(false);
    });

    it("checks substring in string", () => {
      expect(evalExpr('"ell" in "hello"')).toBe(true);
      expect(evalExpr('"xyz" in "hello"')).toBe(false);
    });

    it("checks key in object", () => {
      expect(evalExpr('"a" in obj', { obj: { a: 1, b: 2 } })).toBe(true);
      expect(evalExpr('"c" in obj', { obj: { a: 1, b: 2 } })).toBe(false);
    });

    it("evaluates not in", () => {
      expect(evalExpr('"x" not in ["a", "b"]')).toBe(true);
      expect(evalExpr('"a" not in ["a", "b"]')).toBe(false);
    });
  });

  describe("ternary operator", () => {
    it("returns consequent when true", () => {
      expect(evalExpr("true ? 1 : 2")).toBe(1);
    });

    it("returns alternate when false", () => {
      expect(evalExpr("false ? 1 : 2")).toBe(2);
    });

    it("evaluates condition as boolean", () => {
      expect(evalExpr("1 == 1 ? 'yes' : 'no'")).toBe("yes");
    });

    it("throws on non-boolean condition", () => {
      expect(() => evalExpr('1 ? "a" : "b"')).toThrow(/boolean/);
    });
  });

  describe("built-in functions", () => {
    describe("string helpers", () => {
      it("lower converts to lowercase", () => {
        expect(evalExpr('lower("HELLO")')).toBe("hello");
      });

      it("upper converts to uppercase", () => {
        expect(evalExpr('upper("hello")')).toBe("HELLO");
      });

      it("starts_with checks prefix", () => {
        expect(evalBool('starts_with("hello", "hel")')).toBe(true);
        expect(evalBool('starts_with("hello", "xyz")')).toBe(false);
      });

      it("ends_with checks suffix", () => {
        expect(evalBool('ends_with("hello", "llo")')).toBe(true);
        expect(evalBool('ends_with("hello", "xyz")')).toBe(false);
      });

      it("contains checks substring", () => {
        expect(evalBool('contains("hello", "ell")')).toBe(true);
        expect(evalBool('contains("hello", "xyz")')).toBe(false);
      });

      it("split splits string", () => {
        expect(evalExpr('split("a,b,c", ",")')).toEqual(["a", "b", "c"]);
      });
    });

    describe("collection helpers", () => {
      it("len returns string length", () => {
        expect(evalExpr('len("hello")')).toBe(5);
      });

      it("len returns array length", () => {
        expect(evalExpr("len([1, 2, 3])")).toBe(3);
      });
    });

    describe("pattern helpers", () => {
      it("glob_match matches wildcards", () => {
        expect(evalBool('glob_match("hello.world", "hello.*")')).toBe(true);
        expect(evalBool('glob_match("hello.world", "foo.*")')).toBe(false);
      });

      it("glob_match handles **", () => {
        expect(evalBool('glob_match("a.b.c", "a.**")')).toBe(true);
      });

      it("regex_match matches patterns", () => {
        expect(evalBool('regex_match("hello123", "hello\\\\d+")')).toBe(true);
        expect(evalBool('regex_match("hello", "world")')).toBe(false);
      });
    });
  });

  describe("boolean strictness", () => {
    it("rejects implicit truthiness in &&", () => {
      const result = evaluateAsBoolean(parse('claims.sub && true'), {
        bindings: { claims: { sub: "user123" } },
      });
      expect(result.error).toMatch(/boolean/i);
    });

    it("rejects implicit truthiness in ||", () => {
      const result = evaluateAsBoolean(parse("null || true"), {
        bindings: {},
      });
      expect(result.error).toMatch(/boolean/i);
    });

    it("rejects implicit truthiness in ternary", () => {
      const result = evaluateAsBoolean(parse('"truthy" ? true : false'), {
        bindings: {},
      });
      expect(result.error).toMatch(/boolean/i);
    });
  });

  describe("complex expressions", () => {
    it("evaluates policy-like expression", () => {
      const bindings = {
        claims: {
          role: "admin",
          email: "admin@example.com",
        },
      };
      const result = evalBool(
        'claims.role == "admin" && contains(claims.email, "@example.com")',
        bindings
      );
      expect(result).toBe(true);
    });

    it("evaluates nested ternary", () => {
      const result = evalExpr("1 < 2 ? 2 < 3 ? 'a' : 'b' : 'c'");
      expect(result).toBe("a");
    });

    it("handles missing nested properties gracefully", () => {
      expect(evalExpr("a.b.c.d", { a: {} })).toBe(null);
    });
  });

  describe("error handling", () => {
    it("returns error for unknown function", () => {
      const ast = parse("unknown_fn()");
      const result = evaluate(ast, { bindings: {} });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/unknown/i);
    });

    it("returns error for wrong argument count", () => {
      const ast = parse("len()");
      const result = evaluate(ast, { bindings: {} });
      expect(result.success).toBe(false);
    });

    it("returns error for wrong argument type", () => {
      const ast = parse("len(42)");
      const result = evaluate(ast, { bindings: {} });
      expect(result.success).toBe(false);
    });
  });
});
