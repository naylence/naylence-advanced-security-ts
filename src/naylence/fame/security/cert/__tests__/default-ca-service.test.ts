import { DefaultCAService } from "../default-ca-service.js";
import { createTestCA } from "../internal-ca-service.js";

describe("DefaultCAService trust bundle", () => {
  it("produces a trust bundle containing the root certificate", async () => {
    const [rootCertPem, rootKeyPem] = await createTestCA();

    const service = new DefaultCAService({
      caCertPem: rootCertPem,
      caKeyPem: rootKeyPem,
    });

    const bundle = await service.getTrustBundle();

    expect(bundle).not.toBeNull();
    expect(bundle?.roots.length).toBeGreaterThan(0);
    expect(bundle?.roots[0]?.pem).toContain("-----BEGIN CERTIFICATE-----");
    expect(bundle?.version).toBeGreaterThan(0);
    expect(typeof bundle?.issuedAt).toBe("string");
  });
});
