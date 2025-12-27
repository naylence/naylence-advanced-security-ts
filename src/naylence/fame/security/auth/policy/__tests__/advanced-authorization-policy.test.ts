/**
 * Tests for AdvancedAuthorizationPolicy.
 */

import { describe, it, expect } from "@jest/globals";
import { AdvancedAuthorizationPolicy } from "../advanced-authorization-policy.js";
import type { AdvancedAuthorizationPolicyOptions } from "../advanced-authorization-policy.js";
import type { AuthorizationPolicyDefinition } from "@naylence/runtime";

// Type aliases for testing
type MockNode = { id: string };
type MockEnvelope = {
  id?: string;
  to?: string;
  from?: string;
  frame?: { type: string };
  corrId?: string;
};
type MockContext = {
  security?: {
    authorization?: {
      claims?: Record<string, unknown>;
      grantedScopes?: string[];
    };
  };
  originType?: string;
};

function createMockNode(): MockNode {
  return { id: "node-1" };
}

function createMockEnvelope(): MockEnvelope {
  return {
    id: "env-1",
    frame: { type: "action" },
  };
}

function createPolicy(
  definition: AuthorizationPolicyDefinition
): AdvancedAuthorizationPolicy {
  const options: AdvancedAuthorizationPolicyOptions = {
    policyDefinition: definition,
    warnOnUnknownFields: false,
  };
  return new AdvancedAuthorizationPolicy(options);
}

describe("AdvancedAuthorizationPolicy", () => {
  describe("frame_type validation", () => {
    it("accepts valid frame type Data", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "Data",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("accepts valid frame type NodeHello", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "NodeHello",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("accepts array of valid frame types", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: ["Data", "NodeHello", "NodeWelcome"],
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("rejects invalid frame type", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "InvalidFrameType",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*InvalidFrameType.*Must be one of:/
      );
    });

    it("rejects invalid frame type in array", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: ["Data", "BadType", "NodeHello"],
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*BadType.*Must be one of:/
      );
    });

    it("rejects empty frame type string", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "  ",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*value must not be empty/
      );
    });

    it("rejects empty frame type in array", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: ["Data", "  ", "NodeHello"],
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*values must not be empty/
      );
    });

    it("lists all valid frame types in error message", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "WrongType",
          },
        ],
        default_effect: "deny",
      };

      try {
        createPolicy(definition);
        throw new Error("Should have thrown");
      } catch (error) {
        const message = (error as Error).message;
        // Verify error message includes common frame types
        expect(message).toContain("Data");
        expect(message).toContain("NodeHello");
        expect(message).toContain("NodeWelcome");
        expect(message).toContain("DeliveryAck");
      }
    });

    it("normalizes frame type to lowercase for matching", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "Data", // Uppercase in policy
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = {
        id: "env-1",
        frame: { type: "data" }, // Lowercase in envelope
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("rejects bypassed frame type AddressBindAck", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "AddressBindAck",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*AddressBindAck.*Must be one of:/
      );
    });

    it("rejects bypassed frame type CapabilityAdvertiseAck", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "CapabilityAdvertiseAck",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).toThrow(
        /Invalid frame_type in rule.*CapabilityAdvertiseAck.*Must be one of:/
      );
    });

    it("accepts valid frame type SecureOpen", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "SecureOpen",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("accepts valid frame type SecureAccept", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "SecureAccept",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("accepts valid frame type SecureClose", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: "SecureClose",
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });

    it("accepts all enforceable frame types", () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            frame_type: [
              "Data",
              "DeliveryAck",
              "NodeAttach",
              "AddressBind",
              "AddressUnbind",
              "CapabilityAdvertise",
              "CapabilityWithdraw",
              "CreditUpdate",
              "NodeHello",
              "NodeWelcome",
              "NodeAttachAck",
              "NodeHeartbeat",
              "NodeHeartbeatAck",
              "KeyAnnounce",
              "KeyRequest",
              "SecureOpen",
              "SecureAccept",
              "SecureClose",
            ],
          },
        ],
        default_effect: "deny",
      };

      expect(() => createPolicy(definition)).not.toThrow();
    });
  });

  describe("basic rule matching without when", () => {
    it("matches allow rule without when expression", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("matches deny rule without when expression", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "deny",
            action: "*",
          },
        ],
        default_effect: "allow",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("deny");
    });

    it("falls back to default when no rules match", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "Connect",  // Only matches Connect, not *
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "DeliverLocal"  // Different action
      );

      expect(result.effect).toBe("deny");
    });
  });

  describe("when expression evaluation", () => {
    it("allows when expression is true", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: 'claims.role == "admin"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { role: "admin" },
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("denies when expression is false", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: 'claims.role == "admin"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { role: "user" },
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule doesn't match because when is false, falls to default
      expect(result.effect).toBe("deny");
    });

    it("checks scope requirements in when", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: 'has_scope("admin")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            grantedScopes: ["admin", "read"],
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("combines claims and scope checks", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: 'claims.role == "admin" && has_scope("write")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { role: "admin" },
            grantedScopes: ["write"],
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
    });
  });

  describe("expression parse error handling", () => {
    it("does not match rule with parse error in when", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: "invalid syntax (((",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      // Rule should not match due to parse error, falls to default
      expect(result.effect).toBe("deny");
    });

    it("includes parse error info in traces", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: "missing_paren(",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      // Check that traces contain error info
      expect(result.evaluationTrace.length).toBeGreaterThan(0);
      const trace = result.evaluationTrace[0];
      expect(trace).toBeDefined();
    });
  });

  describe("when expression runtime error handling", () => {
    it("does not match when expression has type error", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: "claims.value && true",  // claims.value is not boolean
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { value: "string-not-boolean" },
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Type error should cause rule not to match
      expect(result.effect).toBe("deny");
    });
  });

  describe("rule evaluation order", () => {
    it("first matching rule wins", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "deny",
            action: "*",
            when: 'claims.role == "blocked"',
          },
          {
            effect: "allow",
            action: "*",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();

      // Blocked user
      const blockedContext: MockContext = {
        security: {
          authorization: {
            claims: { role: "blocked" },
          },
        },
      };
      const blockedResult = await policy.evaluateRequest(
        node as never,
        envelope as never,
        blockedContext as never,
        "*"
      );
      expect(blockedResult.effect).toBe("deny");

      // Regular user - first deny rule doesn't match, falls to second allow
      const allowedContext: MockContext = {
        security: {
          authorization: {
            claims: { role: "user" },
          },
        },
      };
      const allowedResult = await policy.evaluateRequest(
        node as never,
        envelope as never,
        allowedContext as never,
        "*"
      );
      expect(allowedResult.effect).toBe("allow");
    });
  });

  describe("envelope bindings", () => {
    it("accesses envelope id in when", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: "envelope.id != null",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope: MockEnvelope = {
        id: "env-123",
        frame: { type: "action" },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });
  });

  describe("delivery bindings", () => {
    it("accesses origin_type in when", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            effect: "allow",
            action: "*",
            when: 'delivery.origin_type == "downstream"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        originType: "downstream",
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
    });
  });

  describe("null/undefined handling in when expressions", () => {
    it("handles missing claims.sub with starts_with (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-rule",
            effect: "allow",
            action: "*",
            when: 'starts_with(claims.sub, "node-")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: {},  // sub is missing
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match (starts_with returns false for null)
      expect(result.effect).toBe("deny");
      // Trace should NOT include when_error (expression returned false, not error)
      const ruleTrace = result.evaluationTrace.find(t => t.ruleId === "node-rule");
      expect(ruleTrace).toBeDefined();
      expect(ruleTrace!.expression).toContain("evaluated to false");
    });

    it("handles claims.sub as undefined (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-rule",
            effect: "allow",
            action: "*",
            when: 'starts_with(claims.sub, "node-")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { sub: undefined as unknown as string },  // sub is undefined
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match (undefined normalized to null, starts_with returns false)
      expect(result.effect).toBe("deny");
      // Trace should NOT include when_error
      const ruleTrace = result.evaluationTrace.find(t => t.ruleId === "node-rule");
      expect(ruleTrace).toBeDefined();
      expect(ruleTrace!.expression).not.toContain("error");
    });

    it("handles claims.sub as number (includes error in trace)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-rule",
            effect: "allow",
            action: "*",
            when: 'starts_with(claims.sub, "node-")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { sub: 12345 as unknown as string },  // sub is wrong type
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match (wrong type causes error)
      expect(result.effect).toBe("deny");
      // Trace should include when_error
      const ruleTrace = result.evaluationTrace.find(t => t.ruleId === "node-rule");
      expect(ruleTrace).toBeDefined();
      expect(ruleTrace!.expression).toContain("error");
    });

    it("handles valid claims.sub (rule matches)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-rule",
            effect: "allow",
            action: "*",
            when: 'starts_with(claims.sub, "node-")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { sub: "node-123" },  // valid sub
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule matches
      expect(result.effect).toBe("allow");
      expect(result.matchedRule).toBe("node-rule");
    });

    it("handles null scope in has_scope (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "scope-rule",
            effect: "allow",
            action: "*",
            when: "has_scope(claims.requiredScope)",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { requiredScope: null as unknown as string },
            grantedScopes: ["admin"],
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match (has_scope returns false for null)
      expect(result.effect).toBe("deny");
      // No error in trace
      const ruleTrace = result.evaluationTrace.find(t => t.ruleId === "scope-rule");
      expect(ruleTrace).toBeDefined();
      expect(ruleTrace!.expression).not.toContain("error");
    });

    it("handles contains with missing field (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "email-rule",
            effect: "allow",
            action: "*",
            when: 'contains(claims.email, "@example.com")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: {},  // email is missing
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match (contains returns false for null)
      expect(result.effect).toBe("deny");
    });

    it("handles glob_match with null value (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "pattern-rule",
            effect: "allow",
            action: "*",
            when: 'glob_match(claims.resource, "service.*")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { resource: null as unknown as string },
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match
      expect(result.effect).toBe("deny");
    });

    it("handles regex_match with undefined property (no error)", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "regex-rule",
            effect: "allow",
            action: "*",
            when: 'regex_match(claims.userId, "user-\\\\d+")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: {},  // userId is missing
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      // Rule does NOT match
      expect(result.effect).toBe("deny");
    });

    it("handles ends_with with valid match", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "domain-rule",
            effect: "allow",
            action: "*",
            when: 'ends_with(claims.email, "@corp.example.com")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = createMockNode();
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            claims: { email: "user@corp.example.com" },
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
    });
  });

  describe("parameterized null handling tests", () => {
    it.each([
      // [description, whenExpr, claims, expectedEffect, shouldHaveError]
      ["missing property", 'starts_with(claims.sub, "x")', {}, "deny", false],
      ["null property", 'starts_with(claims.sub, "x")', { sub: null }, "deny", false],
      ["undefined property", 'ends_with(claims.sub, "x")', { sub: undefined }, "deny", false],
      ["wrong type number", 'contains(claims.sub, "x")', { sub: 42 }, "deny", true],
      ["wrong type object", 'glob_match(claims.sub, "*")', { sub: {} }, "deny", true],
      ["valid match", 'starts_with(claims.sub, "test")', { sub: "test-123" }, "allow", false],
      ["valid no match", 'starts_with(claims.sub, "other")', { sub: "test-123" }, "deny", false],
    ])(
      "%s: when expression returns expected effect",
      async (_, whenExpr, claims, expectedEffect, shouldHaveError) => {
        const definition: AuthorizationPolicyDefinition = {
          version: "1.0.0",
          rules: [
            {
              id: "test-rule",
              effect: "allow",
              action: "*",
              when: whenExpr,
            },
          ],
          default_effect: "deny",
        };

        const policy = createPolicy(definition);
        const node = createMockNode();
        const envelope = createMockEnvelope();
        const context: MockContext = {
          security: {
            authorization: { claims: claims as Record<string, unknown> },
          },
        };

        const result = await policy.evaluateRequest(
          node as never,
          envelope as never,
          context as never,
          "*"
        );

        expect(result.effect).toBe(expectedEffect);

        const trace = result.evaluationTrace.find(t => t.ruleId === "test-rule");
        if (shouldHaveError) {
          expect(trace?.expression).toContain("error");
        } else if (expectedEffect === "deny") {
          expect(trace?.expression).not.toContain("error");
        }
      }
    );
  });

  describe("node context in expressions", () => {
    it("provides access to node.id in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-id-check",
            effect: "allow",
            action: "*",
            when: 'node.id == "node-1"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1" };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
      expect(result.matchedRule).toBe("node-id-check");
    });

    it("provides access to node.sid in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "node-sid-check",
            effect: "allow",
            action: "*",
            when: 'node.sid == "production-cluster"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: "production-cluster", provisionalId: "prov-1", physicalPath: "/", hasParent: false, publicUrl: null };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
      expect(result.matchedRule).toBe("node-sid-check");
    });

    it("handles null node.sid correctly", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "null-sid-check",
            effect: "allow",
            action: "*",
            when: "node.sid == null",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: null, provisionalId: "prov-1", physicalPath: "/", hasParent: false, publicUrl: null };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("provides access to node.physicalPath in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "path-check",
            effect: "allow",
            action: "*",
            when: 'starts_with(node.physicalPath, "/systems/prod/")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: null, provisionalId: "prov-1", physicalPath: "/systems/prod/worker-01", hasParent: true, publicUrl: null };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
      expect(result.matchedRule).toBe("path-check");
    });

    it("provides access to node.hasParent in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "parent-check",
            effect: "allow",
            action: "*",
            when: "node.hasParent == true",
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: null, provisionalId: "prov-1", physicalPath: "/child", hasParent: true, publicUrl: null };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("provides access to node.publicUrl in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "url-check",
            effect: "allow",
            action: "*",
            when: 'starts_with(node.publicUrl, "https://secure")',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: null, provisionalId: "prov-1", physicalPath: "/", hasParent: false, publicUrl: "https://secure.example.com" };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("allow");
    });

    it("handles null node.publicUrl correctly", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "null-url-check",
            effect: "deny",
            action: "*",
            when: "node.publicUrl == null",
          },
        ],
        default_effect: "allow",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: null, provisionalId: "prov-1", physicalPath: "/", hasParent: false, publicUrl: null };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("deny");
    });

    it("combines node properties with other context in when expressions", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "combined-check",
            effect: "allow",
            action: "*",
            when: 'node.sid == "prod" && has_scope("admin:write") && envelope.frame.type == "action"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1", sid: "prod", provisionalId: "prov-1", physicalPath: "/", hasParent: false, publicUrl: null };
      const envelope = createMockEnvelope();
      const context: MockContext = {
        security: {
          authorization: {
            grantedScopes: ["admin:write", "read"],
          },
        },
      };

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        context as never,
        "*"
      );

      expect(result.effect).toBe("allow");
      expect(result.matchedRule).toBe("combined-check");
    });

    it("denies when node condition does not match", async () => {
      const definition: AuthorizationPolicyDefinition = {
        version: "1.0.0",
        rules: [
          {
            id: "mismatch-check",
            effect: "allow",
            action: "*",
            when: 'node.id == "different-node"',
          },
        ],
        default_effect: "deny",
      };

      const policy = createPolicy(definition);
      const node = { id: "node-1" };
      const envelope = createMockEnvelope();

      const result = await policy.evaluateRequest(
        node as never,
        envelope as never,
        undefined,
        "*"
      );

      expect(result.effect).toBe("deny");
      const trace = result.evaluationTrace.find((t) => t.ruleId === "mismatch-check");
      expect(trace?.expression).toContain("evaluated to false");
    });
  });
});
