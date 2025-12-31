/**
 * Tests for policy-http authorization profile.
 */

import { Registry } from "@naylence/factory";
import {
  getProfile,
  registerRuntimeFactories,
  AUTHORIZER_FACTORY_BASE_TYPE,
} from "@naylence/runtime";

import { registerAdvancedSecurityFactories } from "../../register-advanced-security-factories.js";
import {
  PROFILE_NAME_POLICY_HTTP,
  ENV_VAR_AUTH_POLICY_URL,
  ENV_VAR_AUTH_POLICY_TIMEOUT_MS,
  ENV_VAR_AUTH_POLICY_CACHE_TTL_MS,
  ENV_VAR_AUTH_POLICY_TOKEN_URL,
  ENV_VAR_AUTH_POLICY_CLIENT_ID,
  ENV_VAR_AUTH_POLICY_CLIENT_SECRET,
  ENV_VAR_AUTH_POLICY_AUDIENCE,
  ENV_VAR_AUTH_POLICY_BEARER_TOKEN,
} from "../policy-http-authorization-profile.js";

describe("policy-http authorization profile", () => {
  beforeAll(async () => {
    await registerRuntimeFactories(Registry);
    await registerAdvancedSecurityFactories(Registry);
  });

  describe("profile registration", () => {
    it("exports PROFILE_NAME_POLICY_HTTP constant", () => {
      expect(PROFILE_NAME_POLICY_HTTP).toBe("policy-http");
    });

    it("exports environment variable constants", () => {
      expect(ENV_VAR_AUTH_POLICY_URL).toBe("FAME_AUTH_POLICY_URL");
      expect(ENV_VAR_AUTH_POLICY_TIMEOUT_MS).toBe("FAME_AUTH_POLICY_TIMEOUT_MS");
      expect(ENV_VAR_AUTH_POLICY_CACHE_TTL_MS).toBe("FAME_AUTH_POLICY_CACHE_TTL_MS");
      expect(ENV_VAR_AUTH_POLICY_TOKEN_URL).toBe("FAME_AUTH_POLICY_TOKEN_URL");
      expect(ENV_VAR_AUTH_POLICY_CLIENT_ID).toBe("FAME_AUTH_POLICY_CLIENT_ID");
      expect(ENV_VAR_AUTH_POLICY_CLIENT_SECRET).toBe("FAME_AUTH_POLICY_CLIENT_SECRET");
      expect(ENV_VAR_AUTH_POLICY_AUDIENCE).toBe("FAME_AUTH_POLICY_AUDIENCE");
      expect(ENV_VAR_AUTH_POLICY_BEARER_TOKEN).toBe("FAME_AUTH_POLICY_BEARER_TOKEN");
    });

    it("registers policy-http profile in the profile registry", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      );
      expect(profile).toBeDefined();
    });

    it("profile has correct structure with PolicyAuthorizer type", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      );
      expect(profile).toMatchObject({
        type: "PolicyAuthorizer",
      });
    });

    it("profile includes JWKS token verifier", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      ) as {
        verifier?: { type?: string };
      };
      expect(profile?.verifier).toMatchObject({
        type: "JWKSJWTTokenVerifier",
      });
    });

    it("profile includes HttpAuthorizationPolicySource", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      ) as {
        policy_source?: { type?: string };
      };
      expect(profile?.policy_source).toMatchObject({
        type: "HttpAuthorizationPolicySource",
      });
    });

    it("profile policy_source has url configured via expression", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      ) as {
        policy_source?: { url?: unknown };
      };
      const urlConfig = profile?.policy_source?.url as string;
      // The url should be an expression reference to ENV_VAR_AUTH_POLICY_URL
      expect(urlConfig).toContain("FAME_AUTH_POLICY_URL");
      expect(urlConfig).toMatch(/^\$\{env:/);
    });

    it("profile policy_source includes token_provider with OAuth2 client credentials", () => {
      const profile = getProfile(
        AUTHORIZER_FACTORY_BASE_TYPE,
        PROFILE_NAME_POLICY_HTTP,
      ) as {
        policy_source?: { token_provider?: { type?: string } };
      };
      expect(profile?.policy_source?.token_provider).toMatchObject({
        type: "OAuth2ClientCredentialsTokenProvider",
      });
    });
  });
});
