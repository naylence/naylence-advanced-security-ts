/**
 * Strict Overlay Security Profile
 *
 * Provides the strict-overlay security profile for advanced security scenarios.
 * This profile requires X.509 certificate-based signing and supports both
 * channel and sealed encryption modes.
 */

import { Expressions } from "@naylence/factory";
import { registerProfile, SECURITY_MANAGER_FACTORY_BASE_TYPE } from "@naylence/runtime";

export const ENV_VAR_DEFAULT_ENCRYPTION_LEVEL = "FAME_DEFAULT_ENCRYPTION_LEVEL";
export const ENV_VAR_AUTHORIZATION_PROFILE = "FAME_AUTHORIZATION_PROFILE";
export const PROFILE_NAME_STRICT_OVERLAY = "strict-overlay";

interface DefaultSecurityManagerConfig {
  type: "DefaultSecurityManager";
  security_policy?: Record<string, unknown>;
  authorizer?: Record<string, unknown>;
  [key: string]: unknown;
}

const STRICT_OVERLAY_PROFILE: DefaultSecurityManagerConfig = {
  type: "DefaultSecurityManager",
  security_policy: {
    type: "DefaultSecurityPolicy",
    signing: {
      signing_material: "x509-chain",
      require_cert_sid_match: true,
      inbound: {
        signature_policy: "required",
        unsigned_violation_action: "nack",
        invalid_signature_action: "nack",
      },
      response: {
        mirror_request_signing: true,
        always_sign_responses: false,
        sign_error_responses: true,
      },
      outbound: {
        default_signing: true,
        sign_sensitive_operations: true,
        sign_if_recipient_expects: true,
      },
    },
    encryption: {
      inbound: {
        allow_plaintext: true,
        allow_channel: true,
        allow_sealed: true,
        plaintext_violation_action: "nack",
        channel_violation_action: "nack",
        sealed_violation_action: "nack",
      },
      response: {
        mirror_request_level: true,
        minimum_response_level: "plaintext",
        escalate_sealed_responses: false,
      },
      outbound: {
        default_level: Expressions.env(
          ENV_VAR_DEFAULT_ENCRYPTION_LEVEL,
          "channel",
        ),
        escalate_if_peer_supports: false,
        prefer_sealed_for_sensitive: false,
      },
    },
  },
  authorizer: {
    type: "AuthorizationProfile",
    profile: Expressions.env(ENV_VAR_AUTHORIZATION_PROFILE, "jwt"),
  },
};

// Register the strict-overlay profile
registerProfile(
  SECURITY_MANAGER_FACTORY_BASE_TYPE,
  PROFILE_NAME_STRICT_OVERLAY,
  STRICT_OVERLAY_PROFILE,
  { source: "advanced-security:strict-overlay-security-profile", allowOverride: true },
);
