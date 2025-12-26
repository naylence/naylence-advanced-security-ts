/**
 * Tests for expression parser.
 */

import { describe, it, expect } from "@jest/globals";
import { parse, ParseError, type AstNode } from "../expr/index.js";

describe("Parser", () => {
  describe("literals", () => {
    it("parses string literal", () => {
      const ast = parse('"hello"');
      expect(ast).toEqual({
        type: "StringLiteral",
        position: 0,
        value: "hello",
      });
    });

    it("parses number literal", () => {
      const ast = parse("42");
      expect(ast).toEqual({
        type: "NumberLiteral",
        position: 0,
        value: 42,
      });
    });

    it("parses decimal number", () => {
      const ast = parse("3.14");
      expect(ast).toEqual({
        type: "NumberLiteral",
        position: 0,
        value: 3.14,
      });
    });

    it("parses true", () => {
      const ast = parse("true");
      expect(ast).toEqual({
        type: "BooleanLiteral",
        position: 0,
        value: true,
      });
    });

    it("parses false", () => {
      const ast = parse("false");
      expect(ast).toEqual({
        type: "BooleanLiteral",
        position: 0,
        value: false,
      });
    });

    it("parses null", () => {
      const ast = parse("null");
      expect(ast).toEqual({
        type: "NullLiteral",
        position: 0,
      });
    });

    it("parses empty array", () => {
      const ast = parse("[]");
      expect(ast).toEqual({
        type: "ArrayLiteral",
        position: 0,
        elements: [],
      });
    });

    it("parses array with elements", () => {
      const ast = parse('["a", "b", "c"]');
      expect(ast.type).toBe("ArrayLiteral");
      const arr = ast as unknown as { elements: AstNode[] };
      expect(arr.elements).toHaveLength(3);
    });
  });

  describe("identifiers", () => {
    it("parses simple identifier", () => {
      const ast = parse("foo");
      expect(ast).toEqual({
        type: "Identifier",
        position: 0,
        name: "foo",
      });
    });
  });

  describe("member access", () => {
    it("parses single member access", () => {
      const ast = parse("claims.sub");
      expect(ast).toEqual({
        type: "MemberAccess",
        position: 6,
        object: {
          type: "Identifier",
          position: 0,
          name: "claims",
        },
        property: "sub",
      });
    });

    it("parses chained member access", () => {
      const ast = parse("envelope.frame.type");
      expect(ast.type).toBe("MemberAccess");
      const outer = ast as unknown as { object: AstNode; property: string };
      expect(outer.property).toBe("type");
      expect(outer.object.type).toBe("MemberAccess");
    });
  });

  describe("index access", () => {
    it("parses numeric index", () => {
      const ast = parse("arr[0]");
      expect(ast.type).toBe("IndexAccess");
      const idx = ast as unknown as { object: AstNode; index: AstNode };
      expect(idx.index.type).toBe("NumberLiteral");
    });

    it("parses string index", () => {
      const ast = parse('obj["key"]');
      expect(ast.type).toBe("IndexAccess");
      const idx = ast as unknown as { object: AstNode; index: AstNode };
      expect(idx.index.type).toBe("StringLiteral");
    });
  });

  describe("function calls", () => {
    it("parses function with no args", () => {
      const ast = parse("now()");
      expect(ast).toEqual({
        type: "FunctionCall",
        position: 3,
        name: "now",
        args: [],
      });
    });

    it("parses function with one arg", () => {
      const ast = parse('has_scope("admin")');
      expect(ast.type).toBe("FunctionCall");
      const fn = ast as unknown as { name: string; args: AstNode[] };
      expect(fn.name).toBe("has_scope");
      expect(fn.args).toHaveLength(1);
    });

    it("parses function with multiple args", () => {
      const ast = parse('starts_with(name, "prefix")');
      expect(ast.type).toBe("FunctionCall");
      const fn = ast as unknown as { name: string; args: AstNode[] };
      expect(fn.name).toBe("starts_with");
      expect(fn.args).toHaveLength(2);
    });
  });

  describe("unary operators", () => {
    it("parses logical not", () => {
      const ast = parse("!flag");
      expect(ast).toEqual({
        type: "UnaryOp",
        position: 0,
        operator: "!",
        operand: {
          type: "Identifier",
          position: 1,
          name: "flag",
        },
      });
    });

    it("parses negation", () => {
      const ast = parse("-5");
      expect(ast).toEqual({
        type: "UnaryOp",
        position: 0,
        operator: "-",
        operand: {
          type: "NumberLiteral",
          position: 1,
          value: 5,
        },
      });
    });

    it("parses double negation", () => {
      const ast = parse("!!flag");
      expect(ast.type).toBe("UnaryOp");
      const outer = ast as unknown as { operand: AstNode };
      expect(outer.operand.type).toBe("UnaryOp");
    });
  });

  describe("binary operators", () => {
    describe("arithmetic", () => {
      it("parses addition", () => {
        const ast = parse("a + b");
        expect(ast.type).toBe("BinaryOp");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("+");
      });

      it("parses subtraction", () => {
        const ast = parse("a - b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("-");
      });

      it("parses multiplication", () => {
        const ast = parse("a * b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("*");
      });

      it("parses division", () => {
        const ast = parse("a / b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("/");
      });

      it("parses modulo", () => {
        const ast = parse("a % b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("%");
      });
    });

    describe("comparison", () => {
      it.each(["<", "<=", ">", ">=", "==", "!="])(
        "parses %s operator",
        (op) => {
          const ast = parse(`a ${op} b`);
          expect(ast.type).toBe("BinaryOp");
          const bin = ast as unknown as { operator: string };
          expect(bin.operator).toBe(op);
        }
      );
    });

    describe("logical", () => {
      it("parses logical and", () => {
        const ast = parse("a && b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("&&");
      });

      it("parses logical or", () => {
        const ast = parse("a || b");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("||");
      });
    });

    describe("membership", () => {
      it("parses 'in'", () => {
        const ast = parse('x in ["a", "b"]');
        expect(ast.type).toBe("BinaryOp");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("in");
      });

      it("parses 'not in'", () => {
        const ast = parse('x not in ["a", "b"]');
        expect(ast.type).toBe("BinaryOp");
        const bin = ast as unknown as { operator: string };
        expect(bin.operator).toBe("not in");
      });
    });
  });

  describe("operator precedence", () => {
    it("multiplication before addition", () => {
      // a + b * c should parse as a + (b * c)
      const ast = parse("a + b * c");
      expect(ast.type).toBe("BinaryOp");
      const bin = ast as unknown as { operator: string; left: AstNode; right: AstNode };
      expect(bin.operator).toBe("+");
      expect(bin.right.type).toBe("BinaryOp");
      const right = bin.right as unknown as { operator: string };
      expect(right.operator).toBe("*");
    });

    it("comparison before logical and", () => {
      // a < b && c < d should parse as (a < b) && (c < d)
      const ast = parse("a < b && c < d");
      expect(ast.type).toBe("BinaryOp");
      const bin = ast as unknown as { operator: string; left: AstNode; right: AstNode };
      expect(bin.operator).toBe("&&");
      expect(bin.left.type).toBe("BinaryOp");
      expect(bin.right.type).toBe("BinaryOp");
    });

    it("logical and before logical or", () => {
      // a && b || c should parse as (a && b) || c
      const ast = parse("a && b || c");
      expect(ast.type).toBe("BinaryOp");
      const bin = ast as unknown as { operator: string; left: AstNode };
      expect(bin.operator).toBe("||");
      expect(bin.left.type).toBe("BinaryOp");
      const left = bin.left as unknown as { operator: string };
      expect(left.operator).toBe("&&");
    });

    it("in before comparison", () => {
      // x in list == true should parse as (x in list) == true
      const ast = parse("x in list == true");
      expect(ast.type).toBe("BinaryOp");
      const bin = ast as unknown as { operator: string; left: AstNode };
      expect(bin.operator).toBe("==");
      expect(bin.left.type).toBe("BinaryOp");
      const left = bin.left as unknown as { operator: string };
      expect(left.operator).toBe("in");
    });

    it("parentheses override precedence", () => {
      // (a + b) * c
      const ast = parse("(a + b) * c");
      expect(ast.type).toBe("BinaryOp");
      const bin = ast as unknown as { operator: string; left: AstNode };
      expect(bin.operator).toBe("*");
      expect(bin.left.type).toBe("BinaryOp");
      const left = bin.left as unknown as { operator: string };
      expect(left.operator).toBe("+");
    });
  });

  describe("ternary operator", () => {
    it("parses simple ternary", () => {
      const ast = parse("a ? b : c");
      expect(ast).toEqual({
        type: "TernaryOp",
        position: 0,
        condition: { type: "Identifier", position: 0, name: "a" },
        consequent: { type: "Identifier", position: 4, name: "b" },
        alternate: { type: "Identifier", position: 8, name: "c" },
      });
    });

    it("parses nested ternary in consequent", () => {
      // a ? (b ? c : d) : e
      const ast = parse("a ? b ? c : d : e");
      expect(ast.type).toBe("TernaryOp");
      const tern = ast as unknown as { consequent: AstNode };
      expect(tern.consequent.type).toBe("TernaryOp");
    });

    it("parses nested ternary in alternate", () => {
      // a ? b : (c ? d : e)
      const ast = parse("a ? b : c ? d : e");
      expect(ast.type).toBe("TernaryOp");
      const tern = ast as unknown as { alternate: AstNode };
      expect(tern.alternate.type).toBe("TernaryOp");
    });
  });

  describe("complex expressions", () => {
    it("parses policy expression", () => {
      const ast = parse(
        'claims.role == "admin" && has_scope("write") || claims.role == "superuser"'
      );
      expect(ast.type).toBe("BinaryOp");
    });

    it("parses member access with function call", () => {
      const ast = parse('starts_with(claims.email, "@example.com")');
      expect(ast.type).toBe("FunctionCall");
    });

    it("parses chained index access", () => {
      const ast = parse('arr[0]["key"]');
      expect(ast.type).toBe("IndexAccess");
    });

    it("parses expression with all literal types", () => {
      const ast = parse('"str" == null ? 0 : true ? 1.5 : false');
      expect(ast.type).toBe("TernaryOp");
    });
  });

  describe("error handling", () => {
    it("throws on unexpected token", () => {
      expect(() => parse("+ a")).toThrow(ParseError);
    });

    it("throws on unclosed parenthesis", () => {
      expect(() => parse("(a + b")).toThrow(ParseError);
    });

    it("throws on unclosed bracket", () => {
      expect(() => parse("[1, 2")).toThrow(ParseError);
    });

    it("throws on missing ternary colon", () => {
      expect(() => parse("a ? b c")).toThrow(ParseError);
    });

    it("throws on trailing tokens", () => {
      expect(() => parse("a b")).toThrow(ParseError);
    });
  });
});
