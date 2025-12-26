/**
 * Tests for secure_hash builtin function
 */

import { describe, it, expect } from "@jest/globals";
import {
  parse,
  evaluate,
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

describe("secure_hash builtin", () => {
  describe("basic behavior", () => {
    it("generates deterministic hash for same input", () => {
      const bindings = { str: "test-value" };
      const result1 = evalExpr('secure_hash(str, 16)', bindings);
      const result2 = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(result1).toBe(result2);
      expect(typeof result1).toBe("string");
      expect((result1 as string).length).toBe(16);
    });

    it("generates different hashes for different inputs", () => {
      const bindings1 = { str: "value-one" };
      const bindings2 = { str: "value-two" };
      
      const hash1 = evalExpr('secure_hash(str, 16)', bindings1);
      const hash2 = evalExpr('secure_hash(str, 16)', bindings2);
      
      expect(hash1).not.toBe(hash2);
    });

    it("respects the length parameter", () => {
      const bindings = { str: "test" };
      
      const hash8 = evalExpr('secure_hash(str, 8)', bindings);
      const hash16 = evalExpr('secure_hash(str, 16)', bindings);
      const hash32 = evalExpr('secure_hash(str, 32)', bindings);
      
      expect((hash8 as string).length).toBe(8);
      expect((hash16 as string).length).toBe(16);
      expect((hash32 as string).length).toBe(32);
    });

    it("handles empty string", () => {
      const bindings = { str: "" };
      const result = evalExpr('secure_hash(str, 10)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(10);
    });

    it("handles strings with special characters", () => {
      const bindings = { str: "hello@world!#$%^&*()" };
      const result = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });

    it("handles unicode strings", () => {
      const bindings = { str: "Hello 世界 🌍" };
      const result = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });

    it("handles very long strings", () => {
      const bindings = { str: "a".repeat(10000) };
      const result = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });
  });

  describe("null handling", () => {
    it("returns empty string for null input", () => {
      const result = evalExpr('secure_hash(null, 16)', {});
      expect(result).toBe("");
    });

    it("returns empty string for missing binding", () => {
      const result = evalExpr('secure_hash(missing, 16)', {});
      expect(result).toBe("");
    });

    it("returns empty string for missing property", () => {
      const bindings = { obj: {} };
      const result = evalExpr('secure_hash(obj.missing, 16)', bindings);
      expect(result).toBe("");
    });

    it("returns empty string for undefined property", () => {
      const bindings = { obj: { prop: undefined } };
      const result = evalExpr('secure_hash(obj.prop, 16)', bindings);
      expect(result).toBe("");
    });

    it("hashes present property value", () => {
      const bindings = { obj: { prop: "value" } };
      const result = evalExpr('secure_hash(obj.prop, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
      expect(result).not.toBe("");
    });
  });

  describe("type validation", () => {
    it("throws for number input", () => {
      const bindings = { num: 42 };
      expect(() => {
        evalExpr('secure_hash(num, 16)', bindings);
      }).toThrow(/input_str must be a string/);
    });

    it("throws for boolean input", () => {
      const bindings = { bool: true };
      expect(() => {
        evalExpr('secure_hash(bool, 16)', bindings);
      }).toThrow(/input_str must be a string/);
    });

    it("throws for array input", () => {
      const bindings = { arr: ["a", "b"] };
      expect(() => {
        evalExpr('secure_hash(arr, 16)', bindings);
      }).toThrow(/input_str must be a string/);
    });

    it("throws for object input", () => {
      const bindings = { obj: { key: "value" } };
      expect(() => {
        evalExpr('secure_hash(obj, 16)', bindings);
      }).toThrow(/input_str must be a string/);
    });

    it("throws for non-number length", () => {
      const bindings = { str: "test", len: "16" };
      expect(() => {
        evalExpr('secure_hash(str, len)', bindings);
      }).toThrow(/length must be a number/);
    });

    it("throws for boolean length", () => {
      const bindings = { str: "test", len: true };
      expect(() => {
        evalExpr('secure_hash(str, len)', bindings);
      }).toThrow(/length must be a number/);
    });
  });

  describe("length validation", () => {
    it("throws for zero length", () => {
      const bindings = { str: "test" };
      expect(() => {
        evalExpr('secure_hash(str, 0)', bindings);
      }).toThrow(/length must be a positive integer/);
    });

    it("throws for negative length", () => {
      const bindings = { str: "test" };
      expect(() => {
        evalExpr('secure_hash(str, -5)', bindings);
      }).toThrow(/length must be a positive integer/);
    });

    it("throws for fractional length", () => {
      const bindings = { str: "test" };
      expect(() => {
        evalExpr('secure_hash(str, 16.5)', bindings);
      }).toThrow(/length must be a positive integer/);
    });

    it("accepts small positive integers", () => {
      const bindings = { str: "test" };
      const result = evalExpr('secure_hash(str, 1)', bindings);
      expect((result as string).length).toBe(1);
    });

    it("accepts large positive integers", () => {
      const bindings = { str: "test" };
      const result = evalExpr('secure_hash(str, 64)', bindings);
      expect((result as string).length).toBe(64);
    });
  });

  describe("argument validation", () => {
    it("throws for zero arguments", () => {
      expect(() => {
        evalExpr('secure_hash()', {});
      }).toThrow(/expected 2 argument/);
    });

    it("throws for one argument", () => {
      const bindings = { str: "test" };
      expect(() => {
        evalExpr('secure_hash(str)', bindings);
      }).toThrow(/expected 2 argument/);
    });

    it("throws for three arguments", () => {
      const bindings = { str: "test" };
      expect(() => {
        evalExpr('secure_hash(str, 16, "extra")', bindings);
      }).toThrow(/expected 2 argument/);
    });
  });

  describe("integration with other builtins", () => {
    it("works with coalesce for safe defaults", () => {
      const bindings = { value: null, default: "fallback" };
      const result = evalExpr(
        'secure_hash(coalesce(value, default), 16)',
        bindings
      );
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
      
      // Should hash "fallback"
      const expected = evalExpr('secure_hash("fallback", 16)', {});
      expect(result).toBe(expected);
    });

    it("works with trim for normalized input", () => {
      const bindings = { str: "  test  " };
      const result1 = evalExpr('secure_hash(trim(str), 16)', bindings);
      const result2 = evalExpr('secure_hash("test", 16)', {});
      
      expect(result1).toBe(result2);
    });

    it("works with exists check", () => {
      const bindings1 = { value: "present" };
      const bindings2 = { value: null };
      
      const result1 = evalExpr(
        'exists(value) && starts_with(secure_hash(value, 16), "a")',
        bindings1
      );
      const result2 = evalExpr(
        'exists(value) && starts_with(secure_hash(value, 16), "a")',
        bindings2
      );
      
      // First should evaluate the hash check
      expect(typeof result1).toBe("boolean");
      // Second should short-circuit at exists
      expect(result2).toBe(false);
    });

    it("composes with string predicates", () => {
      const bindings = { input: "sensitive-data" };
      const hash = evalExpr('secure_hash(input, 16)', bindings) as string;
      
      // Hash should be a valid string for predicate operations
      const result = evalExpr(
        `starts_with(secure_hash(input, 16), "${hash.substring(0, 4)}")`,
        bindings
      );
      
      expect(result).toBe(true);
    });
  });

  describe("determinism verification", () => {
    it("produces consistent hashes across multiple calls", () => {
      const bindings = { str: "consistency-test" };
      const hashes = new Set<string>();
      
      for (let i = 0; i < 10; i++) {
        const hash = evalExpr('secure_hash(str, 20)', bindings);
        hashes.add(hash as string);
      }
      
      expect(hashes.size).toBe(1); // All should be identical
    });

    it("different lengths produce different hashes of same input", () => {
      const bindings = { str: "test" };
      
      const hash10 = evalExpr('secure_hash(str, 10)', bindings);
      const hash20 = evalExpr('secure_hash(str, 20)', bindings);
      
      // Should be different values (different lengths, different hash)
      expect(hash10).not.toBe(hash20);
      expect((hash10 as string).length).toBe(10);
      expect((hash20 as string).length).toBe(20);
    });
  });

  describe("practical use cases", () => {
    it("can generate cache keys", () => {
      const bindings = {
        userId: "user123",
        resource: "document",
        action: "read",
      };
      
      // Combine inputs and hash for cache key
      const result = evalExpr(
        'secure_hash(coalesce(userId, "") + ":" + coalesce(resource, "") + ":" + coalesce(action, ""), 16)',
        bindings
      );
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });

    it("can create content fingerprints", () => {
      const bindings = { content: "This is the document content..." };
      const fingerprint = evalExpr('secure_hash(content, 32)', bindings);
      
      expect(typeof fingerprint).toBe("string");
      expect((fingerprint as string).length).toBe(32);
      
      // Same content should produce same fingerprint
      const fingerprint2 = evalExpr('secure_hash(content, 32)', bindings);
      expect(fingerprint).toBe(fingerprint2);
    });

    it("can generate stable identifiers from user input", () => {
      const bindings = { email: "user@example.com" };
      const userId = evalExpr('secure_hash(lower(trim(email)), 24)', bindings);
      
      expect(typeof userId).toBe("string");
      expect((userId as string).length).toBe(24);
      
      // Should match normalized version
      const normalizedEmail = { email: "  USER@EXAMPLE.COM  " };
      const userId2 = evalExpr('secure_hash(lower(trim(email)), 24)', normalizedEmail);
      expect(userId).toBe(userId2);
    });
  });

  describe("edge cases", () => {
    it("handles whitespace-only strings", () => {
      const bindings = { str: "     " };
      const result = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });

    it("handles newlines and tabs", () => {
      const bindings = { str: "line1\nline2\tword" };
      const result = evalExpr('secure_hash(str, 16)', bindings);
      
      expect(typeof result).toBe("string");
      expect((result as string).length).toBe(16);
    });

    it("treats null length as error", () => {
      const bindings = { str: "test", len: null };
      expect(() => {
        evalExpr('secure_hash(str, len)', bindings);
      }).toThrow(/length must be a number/);
    });
  });
});
