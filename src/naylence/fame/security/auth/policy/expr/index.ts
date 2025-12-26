/**
 * Expression engine for authorization policy `when` expressions.
 *
 * This module provides a deterministic, side-effect-free expression
 * evaluation engine for use in authorization policies.
 *
 * @packageDocumentation
 */

// Core types and utilities
export * from "./ast.js";
export * from "./errors.js";
export * from "./limits.js";

// Tokenizer
export { tokenize, Tokenizer, type Token, type TokenType } from "./tokenizer.js";

// Parser
export { parse, Parser } from "./parser.js";

// Evaluator
export {
  evaluate,
  evaluateAsBoolean,
  Evaluator,
  type EvaluationContext,
  type EvaluationResult,
} from "./evaluator.js";

// Builtins
export {
  BUILTIN_FUNCTIONS,
  callBuiltin,
  isBuiltinFunction,
  getTypeName,
  type ExprValue,
  type BuiltinFunction,
  type BuiltinContext,
} from "./builtins.js";
