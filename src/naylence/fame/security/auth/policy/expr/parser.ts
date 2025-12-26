/**
 * Parser for the expression language.
 *
 * Parses a stream of tokens into an Abstract Syntax Tree (AST).
 * Uses recursive descent parsing with operator precedence.
 *
 * Precedence (lowest to highest):
 * 1. Ternary: ? :
 * 2. Logical OR: ||
 * 3. Logical AND: &&
 * 4. Membership: in, not in
 * 5. Equality: ==, !=
 * 6. Comparison: <, <=, >, >=
 * 7. Additive: +, -
 * 8. Multiplicative: *, /, %
 * 9. Unary: !, -
 * 10. Postfix: . [] ()
 * 11. Primary: literals, identifiers, parentheses
 */

import type {
  AstNode,
  BinaryOperator,
  UnaryOperator,
} from "./ast.js";
import { countAstNodes, calculateAstDepth } from "./ast.js";
import { ParseError } from "./errors.js";
import {
  type ExpressionLimits,
  DEFAULT_EXPRESSION_LIMITS,
  checkAstDepth,
  checkAstNodeCount,
  checkArrayLength,
  checkFunctionArgCount,
} from "./limits.js";
import { tokenize, type Token, type TokenType } from "./tokenizer.js";

/**
 * Parser for expression strings.
 */
export class Parser {
  private readonly tokens: Token[];
  private readonly limits: ExpressionLimits;
  private readonly source: string;
  private current = 0;

  constructor(
    tokens: Token[],
    source: string,
    limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
  ) {
    this.tokens = tokens;
    this.source = source;
    this.limits = limits;
  }

  /**
   * Parses the token stream into an AST.
   */
  public parse(): AstNode {
    const ast = this.parseTernary();

    if (!this.isAtEnd()) {
      const token = this.peek();
      throw new ParseError(
        `Unexpected token: ${token.value || token.type}`,
        token.position,
        this.source
      );
    }

    // Validate AST limits
    const nodeCount = countAstNodes(ast);
    checkAstNodeCount(nodeCount, this.limits);

    const depth = calculateAstDepth(ast);
    checkAstDepth(depth, this.limits);

    return ast;
  }

  // ============================================================
  // Token Helpers
  // ============================================================

  private isAtEnd(): boolean {
    return this.peek().type === "EOF";
  }

  private peek(): Token {
    return this.tokens[this.current] as Token;
  }

  private previous(): Token {
    return this.tokens[this.current - 1] as Token;
  }

  private advance(): Token {
    if (!this.isAtEnd()) {
      this.current++;
    }
    return this.previous();
  }

  private check(type: TokenType): boolean {
    if (this.isAtEnd()) return false;
    return this.peek().type === type;
  }

  private match(...types: TokenType[]): boolean {
    for (const type of types) {
      if (this.check(type)) {
        this.advance();
        return true;
      }
    }
    return false;
  }

  private consume(type: TokenType, message: string): Token {
    if (this.check(type)) {
      return this.advance();
    }
    const token = this.peek();
    throw new ParseError(message, token.position, this.source);
  }

  // ============================================================
  // Expression Parsing (by precedence, lowest to highest)
  // ============================================================

  /**
   * Parses ternary expressions: condition ? consequent : alternate
   */
  private parseTernary(): AstNode {
    const position = this.peek().position;
    let node = this.parseOr();

    if (this.match("QUESTION")) {
      const consequent = this.parseTernary();
      this.consume("COLON", "Expected ':' in ternary expression");
      const alternate = this.parseTernary();

      node = {
        type: "TernaryOp",
        position,
        condition: node,
        consequent,
        alternate,
      };
    }

    return node;
  }

  /**
   * Parses logical OR: ||
   */
  private parseOr(): AstNode {
    let node = this.parseAnd();

    while (this.match("OR")) {
      const position = this.previous().position;
      const right = this.parseAnd();
      node = {
        type: "BinaryOp",
        position,
        operator: "||" as BinaryOperator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses logical AND: &&
   */
  private parseAnd(): AstNode {
    let node = this.parseEquality();

    while (this.match("AND")) {
      const position = this.previous().position;
      const right = this.parseEquality();
      node = {
        type: "BinaryOp",
        position,
        operator: "&&" as BinaryOperator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses equality: ==, !=
   */
  private parseEquality(): AstNode {
    let node = this.parseMembership();

    while (this.match("EQ", "NE")) {
      const operator = this.previous().type === "EQ" ? "==" : "!=";
      const position = this.previous().position;
      const right = this.parseMembership();
      node = {
        type: "BinaryOp",
        position,
        operator: operator as BinaryOperator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses membership: in, not in
   */
  private parseMembership(): AstNode {
    let node = this.parseComparison();

    while (this.match("IN", "NOT_IN")) {
      const operator = this.previous().type === "IN" ? "in" : "not in";
      const position = this.previous().position;
      const right = this.parseComparison();
      node = {
        type: "BinaryOp",
        position,
        operator: operator as BinaryOperator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses comparison: <, <=, >, >=
   */
  private parseComparison(): AstNode {
    let node = this.parseAdditive();

    while (this.match("LT", "LE", "GT", "GE")) {
      const token = this.previous();
      let operator: BinaryOperator;
      switch (token.type) {
        case "LT":
          operator = "<";
          break;
        case "LE":
          operator = "<=";
          break;
        case "GT":
          operator = ">";
          break;
        case "GE":
          operator = ">=";
          break;
        default:
          throw new ParseError(
            `Unexpected token: ${token.type}`,
            token.position,
            this.source
          );
      }
      const position = token.position;
      const right = this.parseAdditive();
      node = {
        type: "BinaryOp",
        position,
        operator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses additive: +, -
   */
  private parseAdditive(): AstNode {
    let node = this.parseMultiplicative();

    while (this.match("PLUS", "MINUS")) {
      const operator = this.previous().type === "PLUS" ? "+" : "-";
      const position = this.previous().position;
      const right = this.parseMultiplicative();
      node = {
        type: "BinaryOp",
        position,
        operator: operator as BinaryOperator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses multiplicative: *, /, %
   */
  private parseMultiplicative(): AstNode {
    let node = this.parseUnary();

    while (this.match("STAR", "SLASH", "PERCENT")) {
      const token = this.previous();
      let operator: BinaryOperator;
      switch (token.type) {
        case "STAR":
          operator = "*";
          break;
        case "SLASH":
          operator = "/";
          break;
        case "PERCENT":
          operator = "%";
          break;
        default:
          throw new ParseError(
            `Unexpected token: ${token.type}`,
            token.position,
            this.source
          );
      }
      const position = token.position;
      const right = this.parseUnary();
      node = {
        type: "BinaryOp",
        position,
        operator,
        left: node,
        right,
      };
    }

    return node;
  }

  /**
   * Parses unary: !, -
   */
  private parseUnary(): AstNode {
    if (this.match("NOT", "MINUS")) {
      const token = this.previous();
      const operator: UnaryOperator = token.type === "NOT" ? "!" : "-";
      const position = token.position;
      const operand = this.parseUnary();
      return {
        type: "UnaryOp",
        position,
        operator,
        operand,
      };
    }

    return this.parsePostfix();
  }

  /**
   * Parses postfix: . [] ()
   */
  private parsePostfix(): AstNode {
    let node = this.parsePrimary();

    while (true) {
      if (this.match("DOT")) {
        const position = this.previous().position;
        const propToken = this.consume(
          "IDENTIFIER",
          "Expected property name after '.'"
        );
        node = {
          type: "MemberAccess",
          position,
          object: node,
          property: propToken.value,
        };
      } else if (this.match("LBRACKET")) {
        const position = this.previous().position;
        const index = this.parseTernary();
        this.consume("RBRACKET", "Expected ']' after index");
        node = {
          type: "IndexAccess",
          position,
          object: node,
          index,
        };
      } else if (this.match("LPAREN")) {
        // Function call - node must be an identifier
        if (node.type !== "Identifier") {
          throw new ParseError(
            "Only named functions can be called",
            node.position,
            this.source
          );
        }
        const position = this.previous().position;
        const args = this.parseArgumentList();
        checkFunctionArgCount(args.length, this.limits);
        node = {
          type: "FunctionCall",
          position,
          name: node.name,
          args,
        };
      } else {
        break;
      }
    }

    return node;
  }

  /**
   * Parses function argument list (already consumed opening paren).
   */
  private parseArgumentList(): AstNode[] {
    const args: AstNode[] = [];

    if (!this.check("RPAREN")) {
      do {
        args.push(this.parseTernary());
      } while (this.match("COMMA"));
    }

    this.consume("RPAREN", "Expected ')' after function arguments");
    return args;
  }

  /**
   * Parses primary expressions: literals, identifiers, parentheses, arrays.
   */
  private parsePrimary(): AstNode {
    const token = this.peek();
    const position = token.position;

    // Boolean literals
    if (this.match("TRUE")) {
      return { type: "BooleanLiteral", position, value: true };
    }
    if (this.match("FALSE")) {
      return { type: "BooleanLiteral", position, value: false };
    }

    // Null literal
    if (this.match("NULL")) {
      return { type: "NullLiteral", position };
    }

    // String literal
    if (this.match("STRING")) {
      return {
        type: "StringLiteral",
        position,
        value: this.previous().value,
      };
    }

    // Number literal
    if (this.match("NUMBER")) {
      const value = parseFloat(this.previous().value);
      if (!Number.isFinite(value)) {
        throw new ParseError("Invalid number", position, this.source);
      }
      return { type: "NumberLiteral", position, value };
    }

    // Identifier
    if (this.match("IDENTIFIER")) {
      return {
        type: "Identifier",
        position,
        name: this.previous().value,
      };
    }

    // Parenthesized expression
    if (this.match("LPAREN")) {
      const expr = this.parseTernary();
      this.consume("RPAREN", "Expected ')' after expression");
      return expr;
    }

    // Array literal
    if (this.match("LBRACKET")) {
      const elements: AstNode[] = [];

      if (!this.check("RBRACKET")) {
        do {
          elements.push(this.parseTernary());
        } while (this.match("COMMA"));
      }

      this.consume("RBRACKET", "Expected ']' after array elements");
      checkArrayLength(elements.length, this.limits);

      return { type: "ArrayLiteral", position, elements };
    }

    throw new ParseError(
      `Unexpected token: ${token.value || token.type}`,
      position,
      this.source
    );
  }
}

/**
 * Parses an expression string into an AST.
 *
 * @param source - The expression string to parse
 * @param limits - Optional expression limits
 * @returns The parsed AST
 * @throws TokenizerError if tokenization fails
 * @throws ParseError if parsing fails
 */
export function parse(
  source: string,
  limits: ExpressionLimits = DEFAULT_EXPRESSION_LIMITS
): AstNode {
  const tokens = tokenize(source, limits);
  const parser = new Parser(tokens, source, limits);
  return parser.parse();
}
