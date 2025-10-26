import {
  createFameEnvelope,
  type DataFrame,
  type FameEnvelope,
  type SecurityHeader,
} from "@naylence/core";
import {
  EncryptionStatus,
  FIXED_PREFIX_LEN,
  sealedEncrypt,
  urlsafeBase64Encode,
  type KeyProvider,
} from "@naylence/runtime";
import { X25519EncryptionManager } from "../x25519-encryption-manager.js";

const TEST_PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIMgzUQtqu7E5ez12BUxRUm0gLxe5/3prf4bP7AUfWGZa
-----END PRIVATE KEY-----
`;

const TEST_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAFYvRTgF/TAJsD1rUofwDqgAg49S2Ai/mn3Ozga3WDzs=
-----END PUBLIC KEY-----
`;

function pemToRawKey(pem: string): Uint8Array {
  const lines = pem.replace(/\r/g, "").split("\n");
  const base64 = lines
    .filter((line) => !line.startsWith("---") && line.trim().length > 0)
    .join("");
  const bytes = Buffer.from(base64, "base64");
  return Uint8Array.from(bytes.subarray(bytes.length - 32));
}

function createSealedEnvelope(payload: unknown, kid: string): FameEnvelope {
  const payloadWithCodec = { original_codec: null, payload };
  const encoded = new TextEncoder().encode(JSON.stringify(payloadWithCodec));
  const publicKey = pemToRawKey(TEST_PUBLIC_PEM);
  const sealed = sealedEncrypt(encoded, publicKey);
  const prefix = sealed.subarray(0, FIXED_PREFIX_LEN);
  const ciphertext = sealed.subarray(FIXED_PREFIX_LEN);

  const envelope = createFameEnvelope({
    to: "local@fame.fabric",
    frame: {
      type: "Data",
      codec: "b64",
      payload: urlsafeBase64Encode(ciphertext),
    },
  });

  const security =
    (envelope.sec as SecurityHeader | undefined) ?? ({} as SecurityHeader);
  security.enc = {
    alg: "ECDH-ES+A256GCM",
    kid,
    val: urlsafeBase64Encode(prefix),
  };
  envelope.sec = security;

  return envelope;
}

describe("X25519EncryptionManager sealed encryption", () => {
  it("encrypts data frames without an existing codec", async () => {
    const recipientKeyId = "HlrzKxbvJ2te2wBP";
    const keyProvider: KeyProvider = {
      async getKey(kid) {
        return {
          kid,
          use: "enc",
          kty: "OKP",
          crv: "X25519",
          x: "T4lj8x4rmoq6v2Tn6DQ6ZRueNhZeYZiGzzbugFsNfwY",
        };
      },
      async getKeysForPath() {
        return [];
      },
    };

    const manager = new X25519EncryptionManager({ keyProvider });

    const envelope = createFameEnvelope({
      to: "math@fame.fabric",
      frame: {
        type: "Data",
        payload: {
          jsonrpc: "2.0",
          id: "1",
          method: "add",
          params: { x: 3, y: 4 },
        },
      },
    });

    const frameBefore = envelope.frame as DataFrame;
    expect(frameBefore.codec).toBeUndefined();

    const result = await manager.encryptEnvelope(envelope, {
      recipientKeyId,
    });

    expect(result.status).toBe(EncryptionStatus.OK);
    const frameAfter = envelope.frame as DataFrame;
    expect(typeof frameAfter.payload).toBe("string");
    expect(frameAfter.codec).toBe("b64");
    expect(envelope.sec?.enc?.kid).toBe(recipientKeyId);
    expect(envelope.sec?.enc?.alg).toBe("ECDH-ES+A256GCM");
  });

  it("falls back to crypto provider private key when kid matches provider key", async () => {
    const keyProvider: KeyProvider = {
      async getKey(kid) {
        return {
          kid,
          use: "enc",
          kty: "OKP",
          crv: "X25519",
          x: urlsafeBase64Encode(pemToRawKey(TEST_PUBLIC_PEM)),
        };
      },
      async getKeysForPath() {
        return [];
      },
    };

    const cryptoProvider = {
      encryptionPrivatePem: TEST_PRIVATE_PEM,
      encryptionPublicPem: TEST_PUBLIC_PEM,
      encryptionKeyId: "local-key",
    };

    const manager = new X25519EncryptionManager({
      keyProvider,
      cryptoProvider,
    });

    const originalPayload = { jsonrpc: "2.0", id: "1", result: 42 };
    const envelope = createSealedEnvelope(originalPayload, "local-key");

    const decrypted = await manager.decryptEnvelope(envelope);
    const frameAfter = decrypted.frame as DataFrame;

    expect(frameAfter.codec).toBeUndefined();
    expect(frameAfter.payload).toEqual(originalPayload);
    expect(decrypted.sec?.enc).toBeUndefined();
  });

  it("falls back when kid mismatches provider key", async () => {
    const keyProvider: KeyProvider = {
      async getKey(kid) {
        return {
          kid,
          use: "enc",
          kty: "OKP",
          crv: "X25519",
          x: urlsafeBase64Encode(pemToRawKey(TEST_PUBLIC_PEM)),
        };
      },
      async getKeysForPath() {
        return [];
      },
    };

    const cryptoProvider = {
      encryptionPrivatePem: TEST_PRIVATE_PEM,
      encryptionPublicPem: TEST_PUBLIC_PEM,
      encryptionKeyId: "local-key",
    };

    const manager = new X25519EncryptionManager({
      keyProvider,
      cryptoProvider,
    });

    const originalPayload = { jsonrpc: "2.0", id: "1", result: 42 };
    const envelope = createSealedEnvelope(originalPayload, "remote-key");

    const decrypted = await manager.decryptEnvelope(envelope);
    const frameAfter = decrypted.frame as DataFrame;

    expect(frameAfter.codec).toBeUndefined();
    expect(frameAfter.payload).toEqual(originalPayload);
    expect(decrypted.sec?.enc).toBeUndefined();
  });
});
