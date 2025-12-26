/**
 * Resource limits for expression parsing and evaluation.
 *
 * These limits protect against resource exhaustion attacks and
 * overly complex expressions.
 */

/**
 * Expression limits configuration.
 */
export interface ExpressionLimits {
  /** Maximum expression string length in characters */
  readonly maxExpressionLength: number;

  /** Maximum AST depth (nesting level) */
  readonly maxAstDepth: number;

  /** Maximum number of AST nodes */
  readonly maxAstNodes: number;

  /** Maximum regex pattern length */
  readonly maxRegexPatternLength: number;

  /** Maximum glob pattern length */
  readonly maxGlobPatternLength: number;

  /** Maximum string literal length */
  readonly maxStringLength: number;

  /** Maximum array literal length */
  readonly maxArrayLength: number;

  /** Maximum function call arguments */
  readonly maxFunctionArgs: number;

  /** Maximum member access chain depth */
  readonly maxMemberAccessDepth: number;
}

/**
 * Default expression limits.
 *
 * These values are chosen to allow reasonable expressions while
 * preventing resource exhaustion.
 */
export const DEFAULT_EXPRESSION_LIMITS: Readonly<ExpressionLimits> = {
  maxExpressionLength: 4096,
  maxAstDepth: 32,
  maxAstNodes: 256,
  maxRegexPatternLength: 256,
  maxGlobPatternLength: 256,
  maxStringLength: 1024,
  maxArrayLength: 64,
  maxFunctionArgs: 16,
  maxMemberAccessDepth: 16,
} as const;

/**
 * Validates that expression length is within limits.
 */
export function checkExpressionLength(
  expression: string,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (expression.length > limits.maxExpressionLength) {
    throw new Error(
      `Expression length ${expression.length} exceeds limit of ${limits.maxExpressionLength}`
    );
  }
}

/**
 * Validates AST depth during parsing.
 */
export function checkAstDepth(
  depth: number,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (depth > limits.maxAstDepth) {
    throw new Error(
      `AST depth ${depth} exceeds limit of ${limits.maxAstDepth}`
    );
  }
}

/**
 * Validates AST node count during parsing.
 */
export function checkAstNodeCount(
  count: number,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (count > limits.maxAstNodes) {
    throw new Error(
      `AST node count ${count} exceeds limit of ${limits.maxAstNodes}`
    );
  }
}

/**
 * Validates regex pattern length before compilation.
 */
export function checkRegexPatternLength(
  pattern: string,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (pattern.length > limits.maxRegexPatternLength) {
    throw new Error(
      `Regex pattern length ${pattern.length} exceeds limit of ${limits.maxRegexPatternLength}`
    );
  }
}

/**
 * Validates glob pattern length before compilation.
 */
export function checkGlobPatternLength(
  pattern: string,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (pattern.length > limits.maxGlobPatternLength) {
    throw new Error(
      `Glob pattern length ${pattern.length} exceeds limit of ${limits.maxGlobPatternLength}`
    );
  }
}

/**
 * Validates array length during evaluation.
 */
export function checkArrayLength(
  length: number,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (length > limits.maxArrayLength) {
    throw new Error(
      `Array length ${length} exceeds limit of ${limits.maxArrayLength}`
    );
  }
}

/**
 * Validates function argument count.
 */
export function checkFunctionArgCount(
  count: number,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): void {
  if (count > limits.maxFunctionArgs) {
    throw new Error(
      `Function argument count ${count} exceeds limit of ${limits.maxFunctionArgs}`
    );
  }
}
