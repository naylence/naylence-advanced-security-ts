/**
 * Abstract Syntax Tree (AST) node types for the expression language.
 *
 * The AST is produced by the parser and consumed by the evaluator.
 */

/**
 * Base interface for all AST nodes.
 */
export interface AstNodeBase {
  /** Discriminator for node type */
  readonly type: string;
  /** Position in source expression (for error reporting) */
  readonly position: number;
}

// ============================================================
// Literal Nodes
// ============================================================

export interface StringLiteralNode extends AstNodeBase {
  readonly type: "StringLiteral";
  readonly value: string;
}

export interface NumberLiteralNode extends AstNodeBase {
  readonly type: "NumberLiteral";
  readonly value: number;
}

export interface BooleanLiteralNode extends AstNodeBase {
  readonly type: "BooleanLiteral";
  readonly value: boolean;
}

export interface NullLiteralNode extends AstNodeBase {
  readonly type: "NullLiteral";
}

export interface ArrayLiteralNode extends AstNodeBase {
  readonly type: "ArrayLiteral";
  readonly elements: readonly AstNode[];
}

// ============================================================
// Identifier and Access Nodes
// ============================================================

export interface IdentifierNode extends AstNodeBase {
  readonly type: "Identifier";
  readonly name: string;
}

export interface MemberAccessNode extends AstNodeBase {
  readonly type: "MemberAccess";
  readonly object: AstNode;
  readonly property: string;
}

export interface IndexAccessNode extends AstNodeBase {
  readonly type: "IndexAccess";
  readonly object: AstNode;
  readonly index: AstNode;
}

export interface FunctionCallNode extends AstNodeBase {
  readonly type: "FunctionCall";
  readonly name: string;
  readonly args: readonly AstNode[];
}

// ============================================================
// Operator Nodes
// ============================================================

export type UnaryOperator = "!" | "-";

export interface UnaryOpNode extends AstNodeBase {
  readonly type: "UnaryOp";
  readonly operator: UnaryOperator;
  readonly operand: AstNode;
}

export type BinaryOperator =
  | "*"
  | "/"
  | "%"
  | "+"
  | "-"
  | "<"
  | "<="
  | ">"
  | ">="
  | "=="
  | "!="
  | "in"
  | "not in"
  | "&&"
  | "||";

export interface BinaryOpNode extends AstNodeBase {
  readonly type: "BinaryOp";
  readonly operator: BinaryOperator;
  readonly left: AstNode;
  readonly right: AstNode;
}

export interface TernaryOpNode extends AstNodeBase {
  readonly type: "TernaryOp";
  readonly condition: AstNode;
  readonly consequent: AstNode;
  readonly alternate: AstNode;
}

// ============================================================
// Union Type
// ============================================================

export type AstNode =
  | StringLiteralNode
  | NumberLiteralNode
  | BooleanLiteralNode
  | NullLiteralNode
  | ArrayLiteralNode
  | IdentifierNode
  | MemberAccessNode
  | IndexAccessNode
  | FunctionCallNode
  | UnaryOpNode
  | BinaryOpNode
  | TernaryOpNode;

// ============================================================
// AST Utilities
// ============================================================

/**
 * Counts the total number of nodes in an AST.
 */
export function countAstNodes(node: AstNode): number {
  let count = 1;

  switch (node.type) {
    case "StringLiteral":
    case "NumberLiteral":
    case "BooleanLiteral":
    case "NullLiteral":
    case "Identifier":
      return count;

    case "ArrayLiteral":
      for (const element of node.elements) {
        count += countAstNodes(element);
      }
      return count;

    case "MemberAccess":
      return count + countAstNodes(node.object);

    case "IndexAccess":
      return count + countAstNodes(node.object) + countAstNodes(node.index);

    case "FunctionCall":
      for (const arg of node.args) {
        count += countAstNodes(arg);
      }
      return count;

    case "UnaryOp":
      return count + countAstNodes(node.operand);

    case "BinaryOp":
      return count + countAstNodes(node.left) + countAstNodes(node.right);

    case "TernaryOp":
      return (
        count +
        countAstNodes(node.condition) +
        countAstNodes(node.consequent) +
        countAstNodes(node.alternate)
      );
  }
}

/**
 * Calculates the maximum depth of an AST.
 */
export function calculateAstDepth(node: AstNode): number {
  switch (node.type) {
    case "StringLiteral":
    case "NumberLiteral":
    case "BooleanLiteral":
    case "NullLiteral":
    case "Identifier":
      return 1;

    case "ArrayLiteral": {
      let maxChildDepth = 0;
      for (const element of node.elements) {
        maxChildDepth = Math.max(maxChildDepth, calculateAstDepth(element));
      }
      return 1 + maxChildDepth;
    }

    case "MemberAccess":
      return 1 + calculateAstDepth(node.object);

    case "IndexAccess":
      return (
        1 +
        Math.max(calculateAstDepth(node.object), calculateAstDepth(node.index))
      );

    case "FunctionCall": {
      let maxArgDepth = 0;
      for (const arg of node.args) {
        maxArgDepth = Math.max(maxArgDepth, calculateAstDepth(arg));
      }
      return 1 + maxArgDepth;
    }

    case "UnaryOp":
      return 1 + calculateAstDepth(node.operand);

    case "BinaryOp":
      return (
        1 +
        Math.max(calculateAstDepth(node.left), calculateAstDepth(node.right))
      );

    case "TernaryOp":
      return (
        1 +
        Math.max(
          calculateAstDepth(node.condition),
          calculateAstDepth(node.consequent),
          calculateAstDepth(node.alternate)
        )
      );
  }
}

/**
 * Returns a human-readable representation of an AST node for debugging.
 */
export function astToString(node: AstNode, indent = 0): string {
  const prefix = "  ".repeat(indent);

  switch (node.type) {
    case "StringLiteral":
      return `${prefix}String: "${node.value}"`;

    case "NumberLiteral":
      return `${prefix}Number: ${node.value}`;

    case "BooleanLiteral":
      return `${prefix}Boolean: ${node.value}`;

    case "NullLiteral":
      return `${prefix}Null`;

    case "ArrayLiteral":
      return (
        `${prefix}Array:\n` +
        node.elements.map((e) => astToString(e, indent + 1)).join("\n")
      );

    case "Identifier":
      return `${prefix}Identifier: ${node.name}`;

    case "MemberAccess":
      return (
        `${prefix}MemberAccess: .${node.property}\n` +
        astToString(node.object, indent + 1)
      );

    case "IndexAccess":
      return (
        `${prefix}IndexAccess:\n` +
        `${prefix}  object:\n` +
        astToString(node.object, indent + 2) +
        `\n${prefix}  index:\n` +
        astToString(node.index, indent + 2)
      );

    case "FunctionCall":
      return (
        `${prefix}FunctionCall: ${node.name}\n` +
        node.args.map((a) => astToString(a, indent + 1)).join("\n")
      );

    case "UnaryOp":
      return (
        `${prefix}UnaryOp: ${node.operator}\n` +
        astToString(node.operand, indent + 1)
      );

    case "BinaryOp":
      return (
        `${prefix}BinaryOp: ${node.operator}\n` +
        astToString(node.left, indent + 1) +
        "\n" +
        astToString(node.right, indent + 1)
      );

    case "TernaryOp":
      return (
        `${prefix}TernaryOp:\n` +
        `${prefix}  condition:\n` +
        astToString(node.condition, indent + 2) +
        `\n${prefix}  consequent:\n` +
        astToString(node.consequent, indent + 2) +
        `\n${prefix}  alternate:\n` +
        astToString(node.alternate, indent + 2)
      );
  }
}
