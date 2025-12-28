/**
 * Cross-language verification test for secure_hash builtin.
 * 
 * This test prints actual values from TypeScript secure_hash()
 * to verify Python implementation produces identical output.
 */

import { describe, it } from "@jest/globals";
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

describe("secure_hash cross-language verification", () => {
  it("prints test vectors for Python comparison", () => {
    console.log("\n=== TypeScript secure_hash() Test Vectors ===\n");
    
    // Simple string
    const result1 = evalExpr('secure_hash("test-value", 16)', {});
    console.log(`secure_hash('test-value', 16) = '${result1}'`);
    
    // Empty string
    const result2 = evalExpr('secure_hash("", 10)', {});
    console.log(`secure_hash('', 10) = '${result2}'`);
    
    // Special characters
    const result3 = evalExpr('secure_hash("hello@world!#$%^&*()", 16)', {});
    console.log(`secure_hash('hello@world!#$%^&*()', 16) = '${result3}'`);
    
    // Unicode
    const result4 = evalExpr('secure_hash("Hello 世界 🌍", 16)', {});
    console.log(`secure_hash('Hello 世界 🌍', 16) = '${result4}'`);
    
    // Various lengths
    console.log("");
    for (const length of [1, 8, 16, 24, 32]) {
      const result = evalExpr(`secure_hash("test", ${length})`, {});
      console.log(`secure_hash('test', ${length}) = '${result}'`);
    }
    
    // Normalized email
    console.log("");
    const email = evalExpr('secure_hash(lower(trim("user@example.com")), 24)', {});
    console.log(`secure_hash(lower(trim('user@example.com')), 24) = '${email}'`);
    
    console.log("\n===========================================\n");
  });
});
