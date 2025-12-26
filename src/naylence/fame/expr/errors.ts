/**
 * Error types for the expression evaluation engine.
 *
 * All expression errors extend ExpressionError for consistent handling.
 */

/**
 * Base error class for all expression-related errors.
 */
export class ExpressionError extends Error {
  public readonly position?: number;
  public readonly expression?: string;

  constructor(message: string, position?: number, expression?: string) {
    super(message);
    this.name = "ExpressionError";
    this.position = position;
    this.expression = expression;
  }

  /**
   * Returns a formatted error message with position context.
   */
  public formatWithContext(): string {
    if (this.expression === undefined || this.position === undefined) {
      return this.message;
    }

    const pointer = " ".repeat(this.position) + "^";
    return `${this.message}\n  ${this.expression}\n  ${pointer}`;
  }
}

/**
 * Error thrown during tokenization (lexical analysis).
 */
export class TokenizerError extends ExpressionError {
  constructor(message: string, position?: number, expression?: string) {
    super(message, position, expression);
    this.name = "TokenizerError";
  }
}

/**
 * Error thrown during parsing (syntax analysis).
 */
export class ParseError extends ExpressionError {
  constructor(message: string, position?: number, expression?: string) {
    super(message, position, expression);
    this.name = "ParseError";
  }
}

/**
 * Error thrown during evaluation (runtime error).
 */
export class EvaluationError extends ExpressionError {
  public readonly path?: string;

  constructor(
    message: string,
    position?: number,
    expression?: string,
    path?: string
  ) {
    super(message, position, expression);
    this.name = "EvaluationError";
    this.path = path;
  }
}

/**
 * Error thrown for type mismatches during evaluation.
 */
export class TypeError extends EvaluationError {
  public readonly expected: string;
  public readonly actual: string;

  constructor(
    expected: string,
    actual: string,
    position?: number,
    expression?: string
  ) {
    super(
      `Type error: expected ${expected}, got ${actual}`,
      position,
      expression
    );
    this.name = "TypeError";
    this.expected = expected;
    this.actual = actual;
  }
}

/**
 * Error thrown when expression limits are exceeded.
 */
export class LimitExceededError extends ExpressionError {
  public readonly limitName: string;
  public readonly limit: number;
  public readonly actual: number;

  constructor(limitName: string, limit: number, actual: number) {
    super(`Limit exceeded: ${limitName} (limit: ${limit}, actual: ${actual})`);
    this.name = "LimitExceededError";
    this.limitName = limitName;
    this.limit = limit;
    this.actual = actual;
  }
}

/**
 * Error thrown when a built-in function encounters an error.
 */
export class BuiltinError extends EvaluationError {
  public readonly functionName: string;

  constructor(
    functionName: string,
    message: string,
    position?: number,
    expression?: string
  ) {
    super(`${functionName}: ${message}`, position, expression);
    this.name = "BuiltinError";
    this.functionName = functionName;
  }
}
