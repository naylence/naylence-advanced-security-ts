/**
 * Tests for expression tokenizer.
 */

import { describe, it, expect } from "@jest/globals";
import { tokenize, TokenizerError } from "../index.js";

describe("Tokenizer", () => {
  describe("literals", () => {
    it("tokenizes string literals with double quotes", () => {
      const tokens = tokenize('"hello"');
      expect(tokens).toHaveLength(2);
      expect(tokens[0]).toEqual({
        type: "STRING",
        value: "hello",
        position: 0,
      });
      expect(tokens[1]?.type).toBe("EOF");
    });

    it("tokenizes string literals with single quotes", () => {
      const tokens = tokenize("'world'");
      expect(tokens[0]).toEqual({
        type: "STRING",
        value: "world",
        position: 0,
      });
    });

    it("tokenizes escape sequences in strings", () => {
      const tokens = tokenize('"line1\\nline2\\ttab"');
      expect(tokens[0]?.value).toBe("line1\nline2\ttab");
    });

    it("tokenizes escaped quotes in strings", () => {
      const tokens = tokenize('"say \\"hello\\""');
      expect(tokens[0]?.value).toBe('say "hello"');
    });

    it("throws on unterminated string", () => {
      expect(() => tokenize('"unterminated')).toThrow(TokenizerError);
    });

    it("tokenizes integer literals", () => {
      const tokens = tokenize("42");
      expect(tokens[0]).toEqual({
        type: "NUMBER",
        value: "42",
        position: 0,
      });
    });

    it("tokenizes decimal literals", () => {
      const tokens = tokenize("3.14159");
      expect(tokens[0]).toEqual({
        type: "NUMBER",
        value: "3.14159",
        position: 0,
      });
    });

    it("tokenizes scientific notation", () => {
      const tokens = tokenize("1.5e10");
      expect(tokens[0]).toEqual({
        type: "NUMBER",
        value: "1.5e10",
        position: 0,
      });
    });

    it("tokenizes negative exponent", () => {
      const tokens = tokenize("2.5E-3");
      expect(tokens[0]).toEqual({
        type: "NUMBER",
        value: "2.5E-3",
        position: 0,
      });
    });

    it("tokenizes boolean true", () => {
      const tokens = tokenize("true");
      expect(tokens[0]).toEqual({
        type: "TRUE",
        value: "true",
        position: 0,
      });
    });

    it("tokenizes boolean false", () => {
      const tokens = tokenize("false");
      expect(tokens[0]).toEqual({
        type: "FALSE",
        value: "false",
        position: 0,
      });
    });

    it("tokenizes null", () => {
      const tokens = tokenize("null");
      expect(tokens[0]).toEqual({
        type: "NULL",
        value: "null",
        position: 0,
      });
    });
  });

  describe("identifiers", () => {
    it("tokenizes simple identifiers", () => {
      const tokens = tokenize("foo");
      expect(tokens[0]).toEqual({
        type: "IDENTIFIER",
        value: "foo",
        position: 0,
      });
    });

    it("tokenizes identifiers with underscores", () => {
      const tokens = tokenize("_private_var");
      expect(tokens[0]?.value).toBe("_private_var");
    });

    it("tokenizes identifiers with numbers", () => {
      const tokens = tokenize("var123");
      expect(tokens[0]?.value).toBe("var123");
    });
  });

  describe("operators", () => {
    it("tokenizes comparison operators", () => {
      const tokens = tokenize("< <= > >= == !=");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["LT", "LE", "GT", "GE", "EQ", "NE"]);
    });

    it("tokenizes logical operators", () => {
      const tokens = tokenize("&& || !");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["AND", "OR", "NOT"]);
    });

    it("tokenizes arithmetic operators", () => {
      const tokens = tokenize("+ - * / %");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["PLUS", "MINUS", "STAR", "SLASH", "PERCENT"]);
    });

    it("tokenizes ternary operators", () => {
      const tokens = tokenize("? :");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["QUESTION", "COLON"]);
    });

    it("tokenizes 'in' keyword", () => {
      const tokens = tokenize("x in list");
      expect(tokens[1]?.type).toBe("IN");
    });

    it("tokenizes 'not in' as single token", () => {
      const tokens = tokenize("x not in list");
      expect(tokens[1]?.type).toBe("NOT_IN");
      expect(tokens[1]?.value).toBe("not in");
    });
  });

  describe("delimiters", () => {
    it("tokenizes parentheses", () => {
      const tokens = tokenize("()");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["LPAREN", "RPAREN"]);
    });

    it("tokenizes brackets", () => {
      const tokens = tokenize("[]");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["LBRACKET", "RBRACKET"]);
    });

    it("tokenizes dot and comma", () => {
      const tokens = tokenize(".,");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["DOT", "COMMA"]);
    });
  });

  describe("complex expressions", () => {
    it("tokenizes member access", () => {
      const tokens = tokenize("claims.sub");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["IDENTIFIER", "DOT", "IDENTIFIER"]);
    });

    it("tokenizes function call", () => {
      const tokens = tokenize('has_scope("admin")');
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["IDENTIFIER", "LPAREN", "STRING", "RPAREN"]);
    });

    it("tokenizes index access", () => {
      const tokens = tokenize("arr[0]");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["IDENTIFIER", "LBRACKET", "NUMBER", "RBRACKET"]);
    });

    it("tokenizes complex expression", () => {
      const tokens = tokenize(
        'claims.roles[0] == "admin" && has_scope("write")'
      );
      expect(tokens.length).toBeGreaterThan(10);
    });

    it("handles whitespace correctly", () => {
      const tokens = tokenize("  a  +  b  ");
      const types = tokens.slice(0, -1).map((t) => t.type);
      expect(types).toEqual(["IDENTIFIER", "PLUS", "IDENTIFIER"]);
    });
  });

  describe("error handling", () => {
    it("throws on invalid character", () => {
      expect(() => tokenize("a @ b")).toThrow(TokenizerError);
    });

    it("throws on single &", () => {
      expect(() => tokenize("a & b")).toThrow(TokenizerError);
    });

    it("throws on single |", () => {
      expect(() => tokenize("a | b")).toThrow(TokenizerError);
    });

    it("throws on single =", () => {
      expect(() => tokenize("a = b")).toThrow(TokenizerError);
    });

    it("throws on invalid escape sequence", () => {
      expect(() => tokenize('"invalid\\q"')).toThrow(TokenizerError);
    });

    it("throws on newline in string", () => {
      expect(() => tokenize('"line1\nline2"')).toThrow(TokenizerError);
    });
  });
});
