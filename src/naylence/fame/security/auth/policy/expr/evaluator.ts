/**
 * Expression evaluator.
 *
 * Evaluates an AST against a set of variable bindings and returns a value.
 */

import type { AstNode, BinaryOperator, UnaryOperator } from "./ast.js";
import {
  callBuiltin,
  getTypeName,
  type BuiltinContext,
  type ExprValue,
} from "./builtins.js";
import { EvaluationError, TypeError } from "./errors.js";
import {
  type ExpressionLimits,
  DEFAULT_EXPRESSION_LIMITS,
} from "./limits.js";

/**
 * Evaluation context with variable bindings.
 */
export interface EvaluationContext {
  /** Variable bindings (claims, envelope, delivery, time) */
  readonly bindings: Readonly<Record<string, ExprValue>>;
  /** Granted scopes for scope helper functions */
  readonly grantedScopes?: readonly string[];
  /** Expression limits */
  readonly limits?: ExpressionLimits;
  /** Source expression for error reporting */
  readonly source?: string;
}

/**
 * Result of expression evaluation with trace information.
 */
export interface EvaluationResult {
  /** The evaluated value */
  readonly value: ExprValue;
  /** Whether evaluation succeeded */
  readonly success: boolean;
  /** Error message if evaluation failed */
  readonly error?: string;
}

/**
 * Evaluates an AST node and returns the result.
 */
export class Evaluator {
  private readonly context: EvaluationContext;
  private readonly limits: ExpressionLimits;
  private readonly source: string;
  private memberAccessDepth = 0;

  constructor(context: EvaluationContext) {
    this.context = context;
    this.limits = context.limits ?? DEFAULT_EXPRESSION_LIMITS;
    this.source = context.source ?? "";
  }

  /**
   * Evaluates an AST node and returns the value.
   */
  public evaluate(node: AstNode): ExprValue {
    switch (node.type) {
      case "StringLiteral":
        return node.value;

      case "NumberLiteral":
        return node.value;

      case "BooleanLiteral":
        return node.value;

      case "NullLiteral":
        return null;

      case "ArrayLiteral":
        return node.elements.map((e) => this.evaluate(e));

      case "Identifier":
        return this.evaluateIdentifier(node.name, node.position);

      case "MemberAccess":
        return this.evaluateMemberAccess(node);

      case "IndexAccess":
        return this.evaluateIndexAccess(node);

      case "FunctionCall":
        return this.evaluateFunctionCall(node);

      case "UnaryOp":
        return this.evaluateUnaryOp(node.operator, node.operand, node.position);

      case "BinaryOp":
        return this.evaluateBinaryOp(
          node.operator,
          node.left,
          node.right,
          node.position
        );

      case "TernaryOp":
        return this.evaluateTernaryOp(
          node.condition,
          node.consequent,
          node.alternate,
          node.position
        );
    }
  }

  /**
   * Evaluates as boolean with strict type checking.
   */
  public evaluateAsBoolean(node: AstNode): boolean {
    const value = this.evaluate(node);
    if (typeof value !== "boolean") {
      throw new TypeError("boolean", getTypeName(value), node.position, this.source);
    }
    return value;
  }

  private evaluateIdentifier(name: string, _position: number): ExprValue {
    // Check if it's a top-level binding
    if (name in this.context.bindings) {
      return this.context.bindings[name] as ExprValue;
    }

    // Unknown identifier evaluates to null (missing field)
    return null;
  }

  private evaluateMemberAccess(
    node: { object: AstNode; property: string; position: number }
  ): ExprValue {
    // Check member access depth
    this.memberAccessDepth++;
    if (this.memberAccessDepth > this.limits.maxMemberAccessDepth) {
      throw new EvaluationError(
        `Member access depth ${this.memberAccessDepth} exceeds limit of ${this.limits.maxMemberAccessDepth}`,
        node.position,
        this.source
      );
    }

    try {
      const obj = this.evaluate(node.object);

      // Null-safe member access: null.foo -> null
      if (obj === null) {
        return null;
      }

      // Must be an object (not primitive, not array)
      if (typeof obj !== "object" || Array.isArray(obj)) {
        // Type mismatch during access returns null (not error)
        return null;
      }

      const record = obj as Record<string, ExprValue>;
      if (node.property in record) {
        return record[node.property] as ExprValue;
      }

      // Missing property evaluates to null
      return null;
    } finally {
      this.memberAccessDepth--;
    }
  }

  private evaluateIndexAccess(
    node: { object: AstNode; index: AstNode; position: number }
  ): ExprValue {
    const obj = this.evaluate(node.object);
    const index = this.evaluate(node.index);

    // Null-safe index access: null[0] -> null
    if (obj === null) {
      return null;
    }

    // Array access with numeric index
    if (Array.isArray(obj)) {
      if (typeof index !== "number") {
        throw new TypeError(
          "number",
          getTypeName(index),
          node.position,
          this.source
        );
      }
      const intIndex = Math.floor(index);
      if (intIndex < 0 || intIndex >= obj.length) {
        // Out of bounds evaluates to null
        return null;
      }
      return obj[intIndex] as ExprValue;
    }

    // Object access with string key
    if (typeof obj === "object") {
      if (typeof index !== "string") {
        throw new TypeError(
          "string",
          getTypeName(index),
          node.position,
          this.source
        );
      }
      const record = obj as Record<string, ExprValue>;
      if (index in record) {
        return record[index] as ExprValue;
      }
      // Missing key evaluates to null
      return null;
    }

    // Type mismatch during access returns null
    return null;
  }

  private evaluateFunctionCall(
    node: { name: string; args: readonly AstNode[]; position: number }
  ): ExprValue {
    // Evaluate arguments
    const args = node.args.map((arg) => this.evaluate(arg));

    const builtinContext: BuiltinContext = {
      limits: this.limits,
      position: node.position,
      source: this.source,
      grantedScopes: this.context.grantedScopes,
    };

    return callBuiltin(node.name, args, builtinContext);
  }

  private evaluateUnaryOp(
    operator: UnaryOperator,
    operand: AstNode,
    position: number
  ): ExprValue {
    const value = this.evaluate(operand);

    switch (operator) {
      case "!":
        if (typeof value !== "boolean") {
          throw new TypeError(
            "boolean",
            getTypeName(value),
            position,
            this.source
          );
        }
        return !value;

      case "-":
        if (typeof value !== "number") {
          throw new TypeError(
            "number",
            getTypeName(value),
            position,
            this.source
          );
        }
        return -value;
    }
  }

  private evaluateBinaryOp(
    operator: BinaryOperator,
    left: AstNode,
    right: AstNode,
    position: number
  ): ExprValue {
    // Short-circuit evaluation for logical operators
    if (operator === "&&") {
      const leftValue = this.evaluate(left);
      if (typeof leftValue !== "boolean") {
        throw new TypeError(
          "boolean",
          getTypeName(leftValue),
          left.position,
          this.source
        );
      }
      if (!leftValue) return false;

      const rightValue = this.evaluate(right);
      if (typeof rightValue !== "boolean") {
        throw new TypeError(
          "boolean",
          getTypeName(rightValue),
          right.position,
          this.source
        );
      }
      return rightValue;
    }

    if (operator === "||") {
      const leftValue = this.evaluate(left);
      if (typeof leftValue !== "boolean") {
        throw new TypeError(
          "boolean",
          getTypeName(leftValue),
          left.position,
          this.source
        );
      }
      if (leftValue) return true;

      const rightValue = this.evaluate(right);
      if (typeof rightValue !== "boolean") {
        throw new TypeError(
          "boolean",
          getTypeName(rightValue),
          right.position,
          this.source
        );
      }
      return rightValue;
    }

    // Eager evaluation for other operators
    const leftValue = this.evaluate(left);
    const rightValue = this.evaluate(right);

    switch (operator) {
      // Arithmetic
      case "+":
        if (typeof leftValue === "string" && typeof rightValue === "string") {
          return leftValue + rightValue;
        }
        if (typeof leftValue === "number" && typeof rightValue === "number") {
          return leftValue + rightValue;
        }
        throw new EvaluationError(
          `Cannot add ${getTypeName(leftValue)} and ${getTypeName(rightValue)}`,
          position,
          this.source
        );

      case "-":
        if (typeof leftValue !== "number" || typeof rightValue !== "number") {
          throw new EvaluationError(
            `Cannot subtract ${getTypeName(leftValue)} and ${getTypeName(rightValue)}`,
            position,
            this.source
          );
        }
        return leftValue - rightValue;

      case "*":
        if (typeof leftValue !== "number" || typeof rightValue !== "number") {
          throw new EvaluationError(
            `Cannot multiply ${getTypeName(leftValue)} and ${getTypeName(rightValue)}`,
            position,
            this.source
          );
        }
        return leftValue * rightValue;

      case "/":
        if (typeof leftValue !== "number" || typeof rightValue !== "number") {
          throw new EvaluationError(
            `Cannot divide ${getTypeName(leftValue)} and ${getTypeName(rightValue)}`,
            position,
            this.source
          );
        }
        if (rightValue === 0) {
          throw new EvaluationError(
            "Division by zero",
            position,
            this.source
          );
        }
        return leftValue / rightValue;

      case "%":
        if (typeof leftValue !== "number" || typeof rightValue !== "number") {
          throw new EvaluationError(
            `Cannot compute modulo of ${getTypeName(leftValue)} and ${getTypeName(rightValue)}`,
            position,
            this.source
          );
        }
        if (rightValue === 0) {
          throw new EvaluationError(
            "Modulo by zero",
            position,
            this.source
          );
        }
        return leftValue % rightValue;

      // Comparison
      case "<":
      case "<=":
      case ">":
      case ">=":
        return this.evaluateComparison(
          operator,
          leftValue,
          rightValue,
          position
        );

      // Equality
      case "==":
        return this.valuesEqual(leftValue, rightValue);

      case "!=":
        return !this.valuesEqual(leftValue, rightValue);

      // Membership
      case "in":
        return this.evaluateIn(leftValue, rightValue, position);

      case "not in":
        return !this.evaluateIn(leftValue, rightValue, position);
    }
  }

  private evaluateComparison(
    operator: "<" | "<=" | ">" | ">=",
    left: ExprValue,
    right: ExprValue,
    position: number
  ): boolean {
    // Numbers
    if (typeof left === "number" && typeof right === "number") {
      switch (operator) {
        case "<":
          return left < right;
        case "<=":
          return left <= right;
        case ">":
          return left > right;
        case ">=":
          return left >= right;
      }
    }

    // Strings
    if (typeof left === "string" && typeof right === "string") {
      switch (operator) {
        case "<":
          return left < right;
        case "<=":
          return left <= right;
        case ">":
          return left > right;
        case ">=":
          return left >= right;
      }
    }

    throw new EvaluationError(
      `Cannot compare ${getTypeName(left)} and ${getTypeName(right)} with ${operator}`,
      position,
      this.source
    );
  }

  private evaluateIn(
    left: ExprValue,
    right: ExprValue,
    position: number
  ): boolean {
    // String in string (substring check)
    if (typeof left === "string" && typeof right === "string") {
      return right.includes(left);
    }

    // Value in array
    if (Array.isArray(right)) {
      return right.some((item) => this.valuesEqual(left, item));
    }

    // Key in object
    if (typeof right === "object" && right !== null && !Array.isArray(right)) {
      if (typeof left !== "string") {
        throw new EvaluationError(
          `Cannot check if ${getTypeName(left)} is a key in object (expected string)`,
          position,
          this.source
        );
      }
      return left in (right as Record<string, ExprValue>);
    }

    throw new EvaluationError(
      `Cannot check membership: ${getTypeName(left)} in ${getTypeName(right)}`,
      position,
      this.source
    );
  }

  private evaluateTernaryOp(
    condition: AstNode,
    consequent: AstNode,
    alternate: AstNode,
    _position: number
  ): ExprValue {
    const condValue = this.evaluate(condition);

    if (typeof condValue !== "boolean") {
      throw new TypeError(
        "boolean",
        getTypeName(condValue),
        condition.position,
        this.source
      );
    }

    return condValue ? this.evaluate(consequent) : this.evaluate(alternate);
  }

  /**
   * Deep equality check for expression values.
   */
  private valuesEqual(a: ExprValue, b: ExprValue): boolean {
    // Identical primitives or same reference
    if (a === b) return true;

    // Type mismatch
    if (typeof a !== typeof b) return false;

    // null check (both must be null if one is)
    if (a === null || b === null) return false;

    // Arrays
    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      for (let i = 0; i < a.length; i++) {
        if (!this.valuesEqual(a[i] as ExprValue, b[i] as ExprValue)) {
          return false;
        }
      }
      return true;
    }

    // Objects
    if (typeof a === "object" && typeof b === "object") {
      const aKeys = Object.keys(a);
      const bKeys = Object.keys(b);
      if (aKeys.length !== bKeys.length) return false;
      for (const key of aKeys) {
        if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
        const aRecord = a as Record<string, ExprValue>;
        const bRecord = b as Record<string, ExprValue>;
        if (!this.valuesEqual(aRecord[key] as ExprValue, bRecord[key] as ExprValue)) {
          return false;
        }
      }
      return true;
    }

    return false;
  }
}

/**
 * Evaluates an AST against a context and returns the result.
 *
 * @param ast - The AST to evaluate
 * @param context - The evaluation context with bindings
 * @returns The evaluation result
 */
export function evaluate(
  ast: AstNode,
  context: EvaluationContext
): EvaluationResult {
  try {
    const evaluator = new Evaluator(context);
    const value = evaluator.evaluate(ast);
    return { value, success: true };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : String(error);
    return { value: null, success: false, error: message };
  }
}

/**
 * Evaluates an AST as a boolean condition.
 *
 * @param ast - The AST to evaluate
 * @param context - The evaluation context with bindings
 * @returns true if the condition is met, false otherwise (including errors)
 */
export function evaluateAsBoolean(
  ast: AstNode,
  context: EvaluationContext
): { value: boolean; error?: string } {
  try {
    const evaluator = new Evaluator(context);
    const value = evaluator.evaluateAsBoolean(ast);
    return { value };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : String(error);
    return { value: false, error: message };
  }
}
