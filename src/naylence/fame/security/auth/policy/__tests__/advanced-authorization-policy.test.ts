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
});
