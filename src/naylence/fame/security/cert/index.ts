export {
	validateJwkX5cCertificate,
	type ValidateJwkX5cCertificateOptions,
	type ValidateJwkX5cCertificateResult,
} from "./util.js";
export { GRANT_PURPOSE_CA_SIGN } from "./grants.js";
export {
	DefaultCertificateManager,
	type DefaultCertificateManagerOptions,
	type SigningConfigInstance as DefaultCertificateManagerSigningConfigInstance,
} from "./default-certificate-manager.js";
export {
	DefaultCertificateManagerFactory,
	FACTORY_META as DEFAULT_CERTIFICATE_MANAGER_FACTORY_META,
	type DefaultCertificateManagerConfig,
} from "./default-certificate-manager-factory.js";

// Certificate Authority (CA) types and services
export {
	type Authorizer,
	type CertificateSigningRequest,
	type CertificateIssuanceResponse,
	CAService,
	CertificateRequestError,
	type CertificateInfo,
} from "./ca-types.js";
export {
	CAServiceClient,
	extractCertificateInfo,
	formatCertificateInfo,
	type HttpConnectionGrant,
	type CertificateRequestResponse,
	ENV_VAR_FAME_CA_SERVICE_URL,
} from "./ca-service-client.js";
export {
	CASigningService,
	type CASigningServiceOptions,
	SID_OID,
	LOGICALS_OID,
	NODE_ID_OID,
	createTestCA,
	extractSpiffeIdFromCert,
	extractSidFromCert,
	extractNodeIdFromCert,
	extractLogicalHostsFromCert,
	extractSidFromSpiffeId,
	verifyCertSidIntegrity,
} from "./internal-ca-service.js";
export {
	DefaultCAService,
	type DefaultCAServiceOptions,
	ENV_FAME_CA_CERT_FILE,
	ENV_FAME_CA_CERT_PEM,
	ENV_FAME_CA_KEY_FILE,
	ENV_FAME_CA_KEY_PEM,
	ENV_FAME_INTERMEDIATE_CHAIN_FILE,
	ENV_FAME_INTERMEDIATE_CHAIN_PEM,
	ENV_FAME_SIGNING_CERT_FILE,
	ENV_FAME_SIGNING_CERT_PEM,
	ENV_FAME_SIGNING_KEY_FILE,
	ENV_FAME_SIGNING_KEY_PEM,
} from "./default-ca-service.js";
export {
	CAServiceFactory,
	type CAServiceConfig,
	CA_SERVICE_FACTORY_BASE_TYPE,
} from "./ca-service-factory.js";
export {
	DefaultCAServiceFactory,
	type DefaultCAServiceConfig,
} from "./default-ca-service-factory.js";
