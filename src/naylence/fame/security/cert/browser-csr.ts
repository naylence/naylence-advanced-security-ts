import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import {
	Attributes,
	CertificationRequest,
	CertificationRequestInfo,
} from "@peculiar/asn1-csr";
import {
	AlgorithmIdentifier,
	Attribute,
	AttributeTypeAndValue,
	AttributeValue,
	Extension,
	Extensions,
	GeneralName,
	Name,
	RelativeDistinguishedName,
	SubjectAlternativeName,
	SubjectPublicKeyInfo,
	id_ce_subjectAltName,
} from "@peculiar/asn1-x509";

import { CreatedEd25519Csr } from "./csr-types.js";

const ED25519_OID = "1.3.101.112";
const OID_COMMON_NAME = "2.5.4.3";
const LOGICAL_URI_PREFIX = "naylence://";

export interface CreateEd25519CsrOptions {
	readonly privateKey: CryptoKey;
	readonly publicKey: CryptoKey;
	readonly commonName: string;
	readonly logicals?: readonly string[];
}

function ensureSubtleCrypto(): SubtleCrypto {
	const instance = globalThis.crypto?.subtle;
	if (!instance) {
		throw new Error("WebCrypto subtle API is required to create a CSR");
	}

	return instance;
}

function buildSubject(commonName: string): Name {
	if (!commonName || typeof commonName !== "string") {
		throw new Error("commonName must be a non-empty string");
	}

	return new Name([
		new RelativeDistinguishedName([
			new AttributeTypeAndValue({
				type: OID_COMMON_NAME,
				value: new AttributeValue({ utf8String: commonName }),
			}),
		]),
	]);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);

	if (typeof globalThis.Buffer?.from === "function") {
		return globalThis.Buffer.from(bytes).toString("base64");
	}

	let binary = "";
	const chunkSize = 0x8000;
	for (let offset = 0; offset < bytes.length; offset += chunkSize) {
		const slice = bytes.subarray(offset, offset + chunkSize);
		binary += String.fromCharCode(...slice);
	}

	if (typeof globalThis.btoa !== "function") {
		throw new Error("Base64 encoding not available in this environment");
	}

	return globalThis.btoa(binary);
}

function derToPem(der: ArrayBuffer, label: string): string {
	const base64 = arrayBufferToBase64(der);
	const lines: string[] = [];
	for (let index = 0; index < base64.length; index += 64) {
		lines.push(base64.slice(index, index + 64));
	}

	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export async function createEd25519Csr(
	options: CreateEd25519CsrOptions,
): Promise<CreatedEd25519Csr> {
	const subtle = ensureSubtleCrypto();
	const { privateKey, publicKey, commonName } = options;

	if (!(privateKey instanceof CryptoKey) || privateKey.type !== "private") {
		throw new Error("privateKey must be a CryptoKey of type 'private'");
	}

	if (!(publicKey instanceof CryptoKey) || publicKey.type !== "public") {
		throw new Error("publicKey must be a CryptoKey of type 'public'");
	}

	const subject = buildSubject(commonName);
	const spkiDer = await subtle.exportKey("spki", publicKey);
	const subjectPublicKeyInfo = AsnConvert.parse(
		spkiDer,
		SubjectPublicKeyInfo,
	);

	const attributes = new Attributes();
	const sanitizedLogicals = Array.isArray(options.logicals)
		? options.logicals
				.map((logical) => logical.trim())
				.filter((logical) => logical.length > 0)
		: [];

	if (sanitizedLogicals.length > 0) {
		const san = new SubjectAlternativeName(
			sanitizedLogicals.map(
				(logical) =>
					new GeneralName({
						uniformResourceIdentifier: `${LOGICAL_URI_PREFIX}${logical}`,
					}),
			),
		);

		const extensions = new Extensions([
			new Extension({
				extnID: id_ce_subjectAltName,
				critical: false,
				extnValue: new OctetString(AsnConvert.serialize(san)),
			}),
		]);

		attributes.push(
			new Attribute({
				type: "1.2.840.113549.1.9.14",
				values: [AsnConvert.serialize(extensions)],
			}),
		);
	}

	const requestInfo = new CertificationRequestInfo({
		subject,
		subjectPKInfo: subjectPublicKeyInfo,
		attributes,
	});

	const requestInfoDer = AsnConvert.serialize(requestInfo);
	const signature = await subtle.sign("Ed25519", privateKey, requestInfoDer);

	const certificationRequest = new CertificationRequest({
		certificationRequestInfo: requestInfo,
		signatureAlgorithm: new AlgorithmIdentifier({
			algorithm: ED25519_OID,
		}),
		signature,
	});

	const csrDer = AsnConvert.serialize(certificationRequest);
	const csrPem = derToPem(csrDer, "CERTIFICATE REQUEST");

	return { csrPem, csrDer };
}
