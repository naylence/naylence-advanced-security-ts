/**
 * Tokenizer (lexer) for the expression language.
 *
 * Converts expression strings into a stream of tokens for the parser.
 */

import { TokenizerError } from "./errors.js";
import { checkExpressionLength, type ExpressionLimits } from "./limits.js";

/**
 * Token types produced by the tokenizer.
 */
export type TokenType =
  // Literals
  | "STRING"
  | "NUMBER"
  | "TRUE"
  | "FALSE"
  | "NULL"
  // Identifiers
  | "IDENTIFIER"
  // Operators
  | "PLUS"
  | "MINUS"
  | "STAR"
  | "SLASH"
  | "PERCENT"
  | "LT"
  | "LE"
  | "GT"
  | "GE"
  | "EQ"
  | "NE"
  | "AND"
  | "OR"
  | "NOT"
  | "IN"
  | "NOT_IN"
  | "QUESTION"
  | "COLON"
  // Delimiters
  | "LPAREN"
  | "RPAREN"
  | "LBRACKET"
  | "RBRACKET"
  | "DOT"
  | "COMMA"
  // Special
  | "EOF";

/**
 * A token produced by the tokenizer.
 */
export interface Token {
  readonly type: TokenType;
  readonly value: string;
  readonly position: number;
}

/**
 * Keywords recognized by the tokenizer.
 */
const KEYWORDS: ReadonlyMap<string, TokenType> = new Map([
  ["true", "TRUE"],
  ["false", "FALSE"],
  ["null", "NULL"],
  ["in", "IN"],
  ["not", "NOT"],
]);

/**
 * Checks if a character is a digit.
 */
function isDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

/**
 * Checks if a character can start an identifier.
 */
function isIdentifierStart(ch: string): boolean {
  return (
    (ch >= "a" && ch <= "z") ||
    (ch >= "A" && ch <= "Z") ||
    ch === "_"
  );
}

/**
 * Checks if a character can continue an identifier.
 */
function isIdentifierPart(ch: string): boolean {
  return isIdentifierStart(ch) || isDigit(ch);
}

/**
 * Checks if a character is whitespace.
 */
function isWhitespace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
}

/**
 * Tokenizer for expression strings.
 */
export class Tokenizer {
  private readonly source: string;
  private readonly limits?: ExpressionLimits;
  private position = 0;
  private readonly tokens: Token[] = [];

  constructor(source: string, limits?: ExpressionLimits) {
    this.source = source;
    this.limits = limits;
  }

  /**
   * Tokenizes the source expression and returns all tokens.
   */
  public tokenize(): Token[] {
    checkExpressionLength(this.source, this.limits);

    while (!this.isAtEnd()) {
      this.scanToken();
    }

    this.tokens.push({
      type: "EOF",
      value: "",
      position: this.position,
    });

    return this.tokens;
  }

  private isAtEnd(): boolean {
    return this.position >= this.source.length;
  }

  private peek(): string {
    if (this.isAtEnd()) return "\0";
    return this.source[this.position] as string;
  }

  private peekNext(): string {
    if (this.position + 1 >= this.source.length) return "\0";
    return this.source[this.position + 1] as string;
  }

  private advance(): string {
    return this.source[this.position++] as string;
  }

  private addToken(type: TokenType, value: string, position: number): void {
    this.tokens.push({ type, value, position });
  }

  private scanToken(): void {
    const ch = this.advance();
    const startPosition = this.position - 1;

    // Skip whitespace
    if (isWhitespace(ch)) {
      return;
    }

    // Single-character tokens
    switch (ch) {
      case "(":
        this.addToken("LPAREN", "(", startPosition);
        return;
      case ")":
        this.addToken("RPAREN", ")", startPosition);
        return;
      case "[":
        this.addToken("LBRACKET", "[", startPosition);
        return;
      case "]":
        this.addToken("RBRACKET", "]", startPosition);
        return;
      case ".":
        this.addToken("DOT", ".", startPosition);
        return;
      case ",":
        this.addToken("COMMA", ",", startPosition);
        return;
      case "+":
        this.addToken("PLUS", "+", startPosition);
        return;
      case "-":
        this.addToken("MINUS", "-", startPosition);
        return;
      case "*":
        this.addToken("STAR", "*", startPosition);
        return;
      case "/":
        this.addToken("SLASH", "/", startPosition);
        return;
      case "%":
        this.addToken("PERCENT", "%", startPosition);
        return;
      case "?":
        this.addToken("QUESTION", "?", startPosition);
        return;
      case ":":
        this.addToken("COLON", ":", startPosition);
        return;
    }

    // Two-character operators
    if (ch === "<") {
      if (this.peek() === "=") {
        this.advance();
        this.addToken("LE", "<=", startPosition);
      } else {
        this.addToken("LT", "<", startPosition);
      }
      return;
    }

    if (ch === ">") {
      if (this.peek() === "=") {
        this.advance();
        this.addToken("GE", ">=", startPosition);
      } else {
        this.addToken("GT", ">", startPosition);
      }
      return;
    }

    if (ch === "=") {
      if (this.peek() === "=") {
        this.advance();
        this.addToken("EQ", "==", startPosition);
        return;
      }
      throw new TokenizerError(
        "Unexpected '='. Did you mean '=='?",
        startPosition,
        this.source
      );
    }

    if (ch === "!") {
      if (this.peek() === "=") {
        this.advance();
        this.addToken("NE", "!=", startPosition);
      } else {
        this.addToken("NOT", "!", startPosition);
      }
      return;
    }

    if (ch === "&") {
      if (this.peek() === "&") {
        this.advance();
        this.addToken("AND", "&&", startPosition);
        return;
      }
      throw new TokenizerError(
        "Unexpected '&'. Did you mean '&&'?",
        startPosition,
        this.source
      );
    }

    if (ch === "|") {
      if (this.peek() === "|") {
        this.advance();
        this.addToken("OR", "||", startPosition);
        return;
      }
      throw new TokenizerError(
        "Unexpected '|'. Did you mean '||'?",
        startPosition,
        this.source
      );
    }

    // String literals
    if (ch === '"' || ch === "'") {
      this.scanString(ch, startPosition);
      return;
    }

    // Number literals
    if (isDigit(ch)) {
      this.scanNumber(startPosition);
      return;
    }

    // Identifiers and keywords
    if (isIdentifierStart(ch)) {
      this.scanIdentifier(startPosition);
      return;
    }

    throw new TokenizerError(
      `Unexpected character: '${ch}'`,
      startPosition,
      this.source
    );
  }

  private scanString(quote: string, startPosition: number): void {
    let value = "";

    while (!this.isAtEnd() && this.peek() !== quote) {
      const ch = this.advance();

      if (ch === "\\") {
        // Escape sequence
        if (this.isAtEnd()) {
          throw new TokenizerError(
            "Unterminated string",
            startPosition,
            this.source
          );
        }
        const escaped = this.advance();
        switch (escaped) {
          case "n":
            value += "\n";
            break;
          case "r":
            value += "\r";
            break;
          case "t":
            value += "\t";
            break;
          case "\\":
            value += "\\";
            break;
          case '"':
            value += '"';
            break;
          case "'":
            value += "'";
            break;
          default:
            throw new TokenizerError(
              `Invalid escape sequence: \\${escaped}`,
              this.position - 2,
              this.source
            );
        }
      } else if (ch === "\n" || ch === "\r") {
        throw new TokenizerError(
          "Unterminated string (newline in string literal)",
          startPosition,
          this.source
        );
      } else {
        value += ch;
      }
    }

    if (this.isAtEnd()) {
      throw new TokenizerError(
        "Unterminated string",
        startPosition,
        this.source
      );
    }

    // Consume closing quote
    this.advance();

    this.addToken("STRING", value, startPosition);
  }

  private scanNumber(startPosition: number): void {
    // Back up to include the first digit
    this.position--;

    let value = "";

    // Integer part
    while (isDigit(this.peek())) {
      value += this.advance();
    }

    // Fractional part
    if (this.peek() === "." && isDigit(this.peekNext())) {
      value += this.advance(); // consume '.'
      while (isDigit(this.peek())) {
        value += this.advance();
      }
    }

    // Exponent part
    if (this.peek() === "e" || this.peek() === "E") {
      value += this.advance();
      if (this.peek() === "+" || this.peek() === "-") {
        value += this.advance();
      }
      if (!isDigit(this.peek())) {
        throw new TokenizerError(
          "Invalid number: expected exponent digits",
          startPosition,
          this.source
        );
      }
      while (isDigit(this.peek())) {
        value += this.advance();
      }
    }

    this.addToken("NUMBER", value, startPosition);
  }

  private scanIdentifier(startPosition: number): void {
    // Back up to include the first character
    this.position--;

    let value = "";

    while (isIdentifierPart(this.peek())) {
      value += this.advance();
    }

    // Check for "not in" compound keyword
    const valueLower = value.toLowerCase();
    if (valueLower === "not") {
      // Check if followed by whitespace and "in"
      const savedPosition = this.position;

      // Skip whitespace
      while (isWhitespace(this.peek())) {
        this.advance();
      }

      // Check for "in"
      if (
        this.peek() === "i" &&
        this.peekNext() === "n" &&
        !isIdentifierPart(this.source[this.position + 2] ?? "\0")
      ) {
        this.advance(); // consume 'i'
        this.advance(); // consume 'n'
        this.addToken("NOT_IN", "not in", startPosition);
        return;
      }

      // Not "not in", restore position
      this.position = savedPosition;
    }

    // Check for keyword
    const keywordType = KEYWORDS.get(valueLower);
    if (keywordType) {
      this.addToken(keywordType, value, startPosition);
    } else {
      this.addToken("IDENTIFIER", value, startPosition);
    }
  }
}

/**
 * Tokenizes an expression string into tokens.
 *
 * @param source - The expression string to tokenize
 * @param limits - Optional expression limits
 * @returns Array of tokens
 * @throws TokenizerError if the expression contains invalid tokens
 */
export function tokenize(
  source: string,
  limits?: ExpressionLimits
): Token[] {
  const tokenizer = new Tokenizer(source, limits);
  return tokenizer.tokenize();
}
