/**
 * Browser-friendly entry point that exposes only modules compatible with
 * runtimes lacking Node.js built-ins. Node-specific certificate authority
 * helpers and Fastify bindings are intentionally excluded.
 */

// Import and use the loader to ensure bundlers don't tree-shake it away
import { __advancedSecurityPluginLoader } from "./advanced-security-isomorphic.js";

// Mark as used so bundlers keep the import
if (typeof __advancedSecurityPluginLoader === "undefined") {
  throw new Error("Advanced security plugin loader not initialized");
}

// Package version
export { VERSION } from './version.js';

export {
	validateJwkX5cCertificate,
	type ValidateJwkX5cCertificateOptions,
	type ValidateJwkX5cCertificateResult,
	publicKeyFromX5c,
	type PublicKeyFromX5cOptions,
} from "./naylence/fame/security/cert/util.js";
export {
	createEd25519Csr,
	type CreateEd25519CsrOptions,
} from "./naylence/fame/security/cert/browser-csr.js";
export { type CreatedEd25519Csr } from "./naylence/fame/security/cert/csr-types.js";
export { GRANT_PURPOSE_CA_SIGN } from "./naylence/fame/security/cert/grants.js";
export {
	CAServiceClient,
	type HttpConnectionGrant,
	type CertificateRequestResponse,
	ENV_VAR_FAME_CA_SERVICE_URL,
	extractCertificateInfo,
	formatCertificateInfo,
} from "./naylence/fame/security/cert/ca-service-client.js";

export * from "./naylence/fame/security/encryption/index.js";

export {
	AdvancedEdDSAEnvelopeSignerFactory,
	FACTORY_META as ADVANCED_EDDSA_ENVELOPE_SIGNER_FACTORY_META,
	type EdDSAEnvelopeSignerConfig,
} from "./naylence/fame/security/signing/eddsa-envelope-signer-factory.js";
export {
	AdvancedEdDSAEnvelopeVerifierFactory,
	FACTORY_META as ADVANCED_EDDSA_ENVELOPE_VERIFIER_FACTORY_META,
	type EdDSAEnvelopeVerifierConfig,
} from "./naylence/fame/security/signing/eddsa-envelope-verifier-factory.js";
export {
	EdDSAEnvelopeVerifier,
	type EdDSAEnvelopeVerifierOptions,
	type SigningConfigInstance,
} from "./naylence/fame/security/signing/eddsa-envelope-verifier.js";

export * from "./naylence/fame/security/keys/index.js";

export * from "./naylence/fame/stickiness/index.js";
export * from "./naylence/fame/welcome/index.js";
