import { webcrypto } from "crypto";

import { AsnConvert } from "@peculiar/asn1-schema";
import { GeneralName, SubjectAlternativeName } from "@peculiar/asn1-x509";
import {
  CASigningService,
  LOGICALS_OID,
  NODE_ID_OID,
  SID_OID,
  createTestCA,
} from "../internal-ca-service.js";
import { secureDigest } from "@naylence/runtime";

async function ensureWebCrypto(): Promise<void> {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    globalThis.crypto = webcrypto as unknown as Crypto;
  }
}

async function generateEd25519KeyPair() {
  await ensureWebCrypto();
  const keyPair = await globalThis.crypto.subtle.generateKey(
    {
      name: "Ed25519",
    },
    true,
    ["sign", "verify"],
  );

  const privateKeyDer = await globalThis.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey,
  );
  const publicKeyDer = await globalThis.crypto.subtle.exportKey(
    "spki",
    keyPair.publicKey,
  );

  return {
    privateKeyPem: derToPem(privateKeyDer, "PRIVATE KEY"),
    publicKeyPem: derToPem(publicKeyDer, "PUBLIC KEY"),
  };
}

function derToPem(der: ArrayBuffer, label: string): string {
  const base64 = Buffer.from(new Uint8Array(der)).toString("base64");
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += 64) {
    lines.push(base64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function pemToDer(pem: string): ArrayBuffer {
  const normalized = pem
    .replace(/-----BEGIN[^-]+-----/, "")
    .replace(/-----END[^-]+-----/, "")
    .replace(/\s+/g, "");
  const buffer = Buffer.from(normalized, "base64");
  return buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength,
  );
}

describe("Internal CA service", () => {
  beforeAll(async () => {
    await ensureWebCrypto();
  });

  it("creates a self-signed root CA certificate", async () => {
    const [rootCertPem] = await createTestCA();
    const x509 = await import("@peculiar/x509");
    const cert = new x509.X509Certificate(pemToDer(rootCertPem));

    expect(cert.issuer).toEqual(cert.subject);
    expect(cert.serialNumber).toBeTruthy();
    expect(cert.notAfter.getTime()).toBeGreaterThan(cert.notBefore.getTime());
    expect(cert.publicKey.algorithm.name).toBe("Ed25519");
  });

  it("creates an intermediate CA signed by the root", async () => {
    const [rootCertPem, rootKeyPem] = await createTestCA();
    const caService = new CASigningService({ rootCertPem, rootKeyPem });

    const intermediateKeys = await generateEd25519KeyPair();
    const intermediateCertPem = await caService.createIntermediateCA(
      intermediateKeys.publicKeyPem,
      "Test Intermediate CA",
      ["fame.fabric"],
      365,
    );

    const x509 = await import("@peculiar/x509");
    const rootCert = new x509.X509Certificate(pemToDer(rootCertPem));
    const intermediateCert = new x509.X509Certificate(
      pemToDer(intermediateCertPem),
    );

    expect(intermediateCert.issuer).toEqual(rootCert.subject);
    expect(intermediateCert.subject).toContain("Test Intermediate CA");
    expect(intermediateCert.notAfter.getTime()).toBeGreaterThan(
      intermediateCert.notBefore.getTime(),
    );
  });

  it("signs node certificates with SPIFFE SAN and custom extensions", async () => {
    const [rootCertPem, rootKeyPem] = await createTestCA();
    const caService = new CASigningService({ rootCertPem, rootKeyPem });

    const nodeKeys = await generateEd25519KeyPair();
    const physicalPath = "/rack/a1/node";
    const nodeSid = secureDigest(physicalPath);
    const nodeCertPem = await caService.signNodeCert(
      nodeKeys.publicKeyPem,
      "node-123",
      nodeSid,
      physicalPath,
      ["edge.fabric"],
      90,
      "naylence.fame",
    );

    const x509 = await import("@peculiar/x509");
    const cert = new x509.X509Certificate(pemToDer(nodeCertPem));

    const sanExtension = cert.getExtension("2.5.29.17");
    expect(sanExtension).not.toBeNull();

    const san = AsnConvert.parse(sanExtension!.value, SubjectAlternativeName);
    const sanUris = (Array.from(san) as GeneralName[])
      .map((item) => item.uniformResourceIdentifier)
      .filter((uri): uri is string => typeof uri === "string");
    const expectedSpiffeUri = `spiffe://naylence.fame/nodes/${nodeSid}`;
    expect(sanUris).toContain(expectedSpiffeUri);

    const sidExtension = cert.getExtension(SID_OID);
    const sidValue = sidExtension
      ? Buffer.from(new Uint8Array(sidExtension.value)).toString("utf8")
      : undefined;
    expect(sidValue).toBe(nodeSid);

    const nodeIdExtension = cert.getExtension(NODE_ID_OID);
    const nodeIdValue = nodeIdExtension
      ? Buffer.from(new Uint8Array(nodeIdExtension.value)).toString("utf8")
      : undefined;
    expect(nodeIdValue).toBe("node-123");

    const logicalsExtension = cert.getExtension(LOGICALS_OID);
    const logicalsValue = logicalsExtension
      ? Buffer.from(new Uint8Array(logicalsExtension.value)).toString("utf8")
      : undefined;
    expect(logicalsValue ? JSON.parse(logicalsValue) : undefined).toEqual([
      "edge.fabric",
    ]);
  });
});
