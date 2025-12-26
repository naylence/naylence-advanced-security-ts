/**
 * Generic expression engine.
 *
 * This module provides a deterministic, side-effect-free expression
 * evaluation engine with injectable built-in functions.
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
  normalizeJsValue,
  type ExprValue,
  type BuiltinFunction,
  type BuiltinContext,
  type FunctionRegistry,
} from "./builtins.js";
