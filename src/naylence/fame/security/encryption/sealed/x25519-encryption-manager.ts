import {
  type DataFrame,
  type FameEnvelope,
  type KeyRequestFrame,
  type EncryptionHeader,
  type SecurityHeader,
  type FameDeliveryContext,
  createFameEnvelope,
  localDeliveryContext,
} from "@naylence/core";
import {
  EncryptionResult,
  type EncryptionManager,
  type EncryptionOptions,
  FIXED_PREFIX_LEN,
} from "@naylence/runtime";
import type { KeyProvider } from "@naylence/runtime";
import type { KeyRecord } from "@naylence/runtime";
import type { CryptoProvider } from "@naylence/runtime";
import { sealedEncrypt, sealedDecrypt } from "@naylence/runtime";
import { urlsafeBase64Encode, urlsafeBase64Decode } from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";
import { NodeLike } from "@naylence/runtime";

const logger = getLogger(
  "naylence.fame.security.encryption.sealed.x25519_encryption_manager",
);

interface X25519EncryptionManagerDependencies {
  readonly keyProvider: KeyProvider;
  readonly nodeLike?: NodeLike | null;
  readonly cryptoProvider?: CryptoProvider | null;
}

type Serializable =
  | Record<string, unknown>
  | unknown[]
  | string
  | number
  | boolean
  | null;

export class X25519EncryptionManager implements EncryptionManager {
  private readonly keyProvider: KeyProvider;
  private readonly nodeLike?: NodeLike | null;
  private readonly cryptoProvider?: CryptoProvider | null;
  private readonly pendingEnvelopes = new Map<string, FameEnvelope[]>();
  private readonly keyRequestsInProgress = new Set<string>();

  constructor({
    keyProvider,
    nodeLike = null,
    cryptoProvider = null,
  }: X25519EncryptionManagerDependencies) {
    this.keyProvider = keyProvider;
    this.nodeLike = nodeLike;
    this.cryptoProvider = cryptoProvider;
  }

  public async encryptEnvelope(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null = null,
  ): Promise<EncryptionResult> {
    if (!this.isDataFrameEnvelope(envelope) || !this.hasPayload(envelope)) {
      return EncryptionResult.skipped(envelope);
    }

    // When requestAddress is provided, SecurityPolicy couldn't find the key.
    // KeyManagementHandler will queue the envelope and send KeyRequest.
    // X25519 should NOT queue here to avoid dual queueing.
    if (opts?.requestAddress) {
      logger.debug("key_not_found_delegating_to_key_management", {
        envelope_id: envelope.id,
        request_address: String(opts.requestAddress),
      });
      return EncryptionResult.queued();
    }

    const { recipPub, recipKid } = await this.resolveRecipientKey(opts);

    if (!recipPub || !recipKid) {
      // This path is for when we have a kid but don't have the key yet
      await this.queueEnvelopeForKey(
        envelope,
        opts,
        recipKid ?? this.deriveTemporaryKeyId(opts),
      );
      return EncryptionResult.queued();
    }

    try {
      return await this.encryptWithKey(envelope, recipPub, recipKid);
    } catch (error) {
      logger.error("x25519_encryption_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return EncryptionResult.skipped(envelope);
    }
  }

  public async decryptEnvelope(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null = null,
  ): Promise<FameEnvelope> {
    if (!this.isDecryptableEnvelope(envelope)) {
      return envelope;
    }

    if (
      !("payload" in envelope.frame) ||
      typeof envelope.frame.payload !== "string"
    ) {
      return envelope;
    }

    try {
      const prefix = urlsafeBase64Decode(envelope.sec!.enc!.val);
      const ciphertext = urlsafeBase64Decode(envelope.frame.payload);
      const blob = new Uint8Array(prefix.length + ciphertext.length);
      blob.set(prefix, 0);
      blob.set(ciphertext, prefix.length);

      const privateKey = await this.resolvePrivateKey(envelope, opts);
      if (!privateKey) {
        throw new Error("Private key material is not available");
      }

      const plaintext = sealedDecrypt(blob, privateKey);
      const payloadWithCodec = JSON.parse(
        new TextDecoder().decode(plaintext),
      ) as {
        payload: unknown;
        original_codec?: string | null;
      };

      const frame = envelope.frame as {
        payload?: unknown;
        codec?: string | null;
      };
      frame.payload = payloadWithCodec.payload as Serializable;
      frame.codec = payloadWithCodec.original_codec ?? undefined;

      if (envelope.sec) {
        envelope.sec.enc = undefined;
        if (!envelope.sec.sig) {
          envelope.sec = undefined;
        }
      }

      return envelope;
    } catch (error) {
      logger.error("x25519_decryption_failed", {
        error: error instanceof Error ? error.message : String(error),
      });
      return envelope;
    }
  }

  public async notifyKeyAvailable(keyId: string): Promise<void> {
    logger.debug("x25519_notify_key_available_called", {
      key_id: keyId,
      pending_keys: Array.from(this.pendingEnvelopes.keys()),
    });

    const queued = this.pendingEnvelopes.get(keyId);
    if (!queued || queued.length === 0) {
      logger.debug("no_queued_envelopes_for_key", {
        key_id: keyId,
        has_queue: this.pendingEnvelopes.has(keyId),
        queue_length: queued?.length ?? 0,
      });
      this.keyRequestsInProgress.delete(keyId);
      return;
    }

    this.pendingEnvelopes.delete(keyId);
    this.keyRequestsInProgress.delete(keyId);

    const node = this.nodeLike;
    if (!node) {
      logger.debug("discarding_queued_envelopes_no_node", {
        key_id: keyId,
        count: queued.length,
      });
      return;
    }

    logger.debug("replaying_envelopes_for_key", {
      key_id: keyId,
      count: queued.length,
    });

    for (const envelope of queued) {
      try {
        await node.deliver(envelope);
      } catch (error) {
        logger.error("failed_to_replay_envelope", {
          key_id: keyId,
          envelope_id: envelope.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  private async encryptWithKey(
    envelope: FameEnvelope,
    recipientPublicKey: Uint8Array,
    recipientKeyId: string,
  ): Promise<EncryptionResult> {
    if (!this.isDataFrameEnvelope(envelope)) {
      return EncryptionResult.skipped(envelope);
    }

    const frame = envelope.frame as DataFrame;
    if (frame.payload === undefined || frame.payload === null) {
      return EncryptionResult.skipped(envelope);
    }

    const payloadWithCodec = {
      original_codec: frame.codec ?? null,
      payload: this.makeJsonSerializable(frame.payload),
    };

    const payloadBytes = new TextEncoder().encode(
      JSON.stringify(payloadWithCodec),
    );
    const sealedBlob = sealedEncrypt(payloadBytes, recipientPublicKey);
    const prefix = sealedBlob.subarray(0, FIXED_PREFIX_LEN);
    const ciphertext = sealedBlob.subarray(FIXED_PREFIX_LEN);

    frame.codec = "b64";
    frame.payload = urlsafeBase64Encode(ciphertext);

    const encryptionHeader: EncryptionHeader = {
      alg: "ECDH-ES+A256GCM",
      kid: recipientKeyId,
      val: urlsafeBase64Encode(prefix),
    };

    if (envelope.sec) {
      envelope.sec.enc = encryptionHeader;
    } else {
      envelope.sec = { enc: encryptionHeader } as SecurityHeader;
    }

    return EncryptionResult.ok(envelope);
  }

  private async resolveRecipientKey(
    opts: EncryptionOptions | null,
  ): Promise<{ recipPub: Uint8Array | null; recipKid: string | null }> {
    if (opts) {
      const directKey = this.extractKeyFromOptions(opts);
      if (directKey) {
        const kid = this.extractRecipientKeyId(opts) ?? "recip-kid-stub";
        return { recipPub: directKey, recipKid: kid };
      }

      const kid = this.extractRecipientKeyId(opts);
      if (kid) {
        const resolved = await this.lookupKeyById(kid);
        if (resolved) {
          return { recipPub: resolved, recipKid: kid };
        }
      }

      if (opts.requestAddress) {
        const addressPath = String(opts.requestAddress);

        // Don't try to resolve locally - this indicates we should request the key
        // The SecurityPolicy is responsible for looking up keys by address
        // This matches Python's design (lines 119-124 in x25519_encryption_manager.py)
        const temporaryKid = `request-${addressPath}`;
        return { recipPub: null, recipKid: temporaryKid };
      }
    }

    return { recipPub: null, recipKid: null };
  }

  private async resolvePrivateKey(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null,
  ): Promise<Uint8Array | null> {
    const header = envelope.sec?.enc;
    const candidateKeys = [
      opts?.privKey,
      opts?.priv_key,
      opts?.privateKey,
      opts?.channelKey,
    ];

    for (const candidate of candidateKeys) {
      const normalized = this.toUint8Array(candidate);
      if (normalized) {
        return normalized;
      }
    }

    const kid =
      header?.kid && header.kid !== "recip-kid-stub" ? header.kid : null;
    if (!kid) {
      const fallback = this.cryptoProvider?.encryptionPrivatePem;
      if (!fallback) {
        return null;
      }
      return this.decodePemToRawKey(fallback, "private");
    }

    const record = await this.safeGetKeyRecord(kid);

    const fromRecord = record ? this.extractPrivateKeyFromRecord(record) : null;
    if (fromRecord) {
      return fromRecord;
    }

    const providerKeyId = this.cryptoProvider?.encryptionKeyId ?? null;
    const providerPem = this.cryptoProvider?.encryptionPrivatePem ?? null;

    if (providerKeyId) {
      const providerRecord =
        kid === providerKeyId
          ? record
          : await this.safeGetKeyRecord(providerKeyId);
      const providerRecordKey = providerRecord
        ? this.extractPrivateKeyFromRecord(providerRecord)
        : null;

      if (providerRecordKey) {
        logger.debug("using_provider_key_record_private_key", {
          kid,
          provider_key_id: providerKeyId,
          mismatched_kid: kid && providerKeyId !== kid ? kid : null,
        });
        return providerRecordKey;
      }
    }

    if (!providerPem) {
      if (kid && providerKeyId && providerKeyId !== kid) {
        logger.debug("crypto_provider_key_id_mismatch_no_private_key", {
          kid,
          provider_key_id: providerKeyId,
        });
      }
      return null;
    }

    const fallbackKey = this.decodePemToRawKey(providerPem, "private");
    if (!fallbackKey) {
      return null;
    }

    if (!kid || providerKeyId === kid) {
      logger.debug("using_crypto_provider_private_key_fallback", {
        kid: kid ?? null,
        provider_key_id: providerKeyId,
      });
    } else {
      logger.warning("crypto_provider_key_id_mismatch_using_private_key", {
        kid,
        provider_key_id: providerKeyId,
        key_record_present: Boolean(record),
      });
    }

    return fallbackKey;
  }

  private async queueEnvelopeForKey(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null,
    recipientKeyId: string,
  ): Promise<void> {
    logger.debug("queueing_envelope_for_sealed_encryption", {
      envelope_id: envelope.id,
      recipient_key_id: recipientKeyId,
      request_address: opts?.requestAddress
        ? String(opts.requestAddress)
        : undefined,
    });

    const queue = this.pendingEnvelopes.get(recipientKeyId) ?? [];
    queue.push(envelope);
    this.pendingEnvelopes.set(recipientKeyId, queue);

    if (!opts?.requestAddress) {
      return;
    }

    const node = this.nodeLike;
    if (!node) {
      return;
    }

    if (this.keyRequestsInProgress.has(recipientKeyId)) {
      return;
    }

    this.keyRequestsInProgress.add(recipientKeyId);

    try {
      // Convert FameAddress to string for the frame schema
      const requestAddressString =
        typeof opts.requestAddress === "string"
          ? opts.requestAddress
          : opts.requestAddress.toString();

      const requestFrame: KeyRequestFrame = {
        type: "KeyRequest",
        address: requestAddressString,
        kid: this.extractRecipientKeyId(opts) ?? undefined,
        physicalPath: node.physicalPath ?? undefined,
      };

      const context: FameDeliveryContext = node.sid
        ? localDeliveryContext(node.sid)
        : localDeliveryContext();

      const envelopeFactory = node.envelopeFactory;
      const keyRequestEnvelope = envelopeFactory
        ? envelopeFactory.createEnvelope({
            to: opts.requestAddress,
            frame: requestFrame,
          })
        : createFameEnvelope({
            to: opts.requestAddress,
            frame: requestFrame,
          });

      await node.deliver(keyRequestEnvelope, context);
    } catch (error) {
      logger.error("failed_to_request_recipient_key", {
        recipient_key_id: recipientKeyId,
        error: error instanceof Error ? error.message : String(error),
      });
      this.keyRequestsInProgress.delete(recipientKeyId);
    }
  }

  private async lookupKeyById(kid: string): Promise<Uint8Array | null> {
    try {
      const record = await this.keyProvider.getKey(kid);
      return this.extractPublicKeyFromRecord(record);
    } catch (error) {
      logger.debug("recipient_key_lookup_failed", {
        kid,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  private async safeGetKeyRecord(
    kid: string | null,
  ): Promise<KeyRecord | null> {
    if (!kid) {
      return null;
    }

    try {
      return await this.keyProvider.getKey(kid);
    } catch (error) {
      logger.debug("private_key_lookup_failed", {
        kid,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  private extractPublicKeyFromRecord(record: KeyRecord): Uint8Array | null {
    const candidates = [
      this.getRecordValue(record, "encryption_public_pem"),
      this.getRecordValue(record, "encryptionPublicPem"),
      this.getRecordValue(record, "public_key"),
      this.getRecordValue(record, "publicKey"),
      this.getRecordValue(record, "encryption_public_key"),
      this.getRecordValue(record, "encryptionPublicKey"),
      this.getRecordValue(record, "x"),
    ];

    for (const candidate of candidates) {
      const normalized = this.decodeKeyMaterial(candidate, "public");
      if (normalized) {
        return normalized;
      }
    }

    return null;
  }

  private extractPrivateKeyFromRecord(record: KeyRecord): Uint8Array | null {
    const candidates = [
      this.getRecordValue(record, "encryption_private_pem"),
      this.getRecordValue(record, "encryptionPrivatePem"),
      this.getRecordValue(record, "private_key"),
      this.getRecordValue(record, "privateKey"),
      this.getRecordValue(record, "d"),
    ];

    for (const candidate of candidates) {
      const normalized = this.decodeKeyMaterial(candidate, "private");
      if (normalized) {
        return normalized;
      }
    }

    return null;
  }

  private decodeKeyMaterial(
    value: unknown,
    keyType: "public" | "private",
  ): Uint8Array | null {
    if (!value) {
      return null;
    }

    if (value instanceof Uint8Array) {
      return value;
    }

    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }

    if (typeof value === "string") {
      if (value.includes("BEGIN")) {
        return this.decodePemToRawKey(value, keyType);
      }

      return this.decodeBase64Flexible(value);
    }

    return null;
  }

  private decodePemToRawKey(
    pem: string,
    keyType: "public" | "private",
  ): Uint8Array | null {
    const lines = pem.replace(/\r/g, "").split("\n");
    const base64Lines = lines.filter(
      (line) => !line.startsWith("---") && line.trim().length > 0,
    );
    if (base64Lines.length === 0) {
      return null;
    }

    const base64 = base64Lines.join("");
    const der = this.decodeBase64Flexible(base64);
    if (!der) {
      logger.debug("pem_decode_failed", {
        key_type: keyType,
      });
      return null;
    }

    if (der.length < 32) {
      return null;
    }

    return der.subarray(der.length - 32);
  }

  private extractKeyFromOptions(opts: EncryptionOptions): Uint8Array | null {
    const candidates = [opts.recipPub, opts.recipientPublicKey, opts.recip_pub];

    for (const candidate of candidates) {
      const normalized = this.toUint8Array(candidate);
      if (normalized) {
        return normalized;
      }
    }

    return null;
  }

  private toUint8Array(value: unknown): Uint8Array | null {
    if (!value) {
      return null;
    }

    if (value instanceof Uint8Array) {
      return value;
    }

    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }

    if (Array.isArray(value)) {
      return Uint8Array.from(value);
    }

    if (typeof value === "string") {
      return this.decodeBase64Flexible(value);
    }

    return null;
  }

  private deriveTemporaryKeyId(opts: EncryptionOptions | null): string {
    if (opts?.requestAddress) {
      return `request-${String(opts.requestAddress)}`;
    }
    return "pending-recipient-key";
  }

  private extractRecipientKeyId(opts: EncryptionOptions): string | null {
    return opts.recipKid ?? opts.recip_kid ?? opts.recipientKeyId ?? null;
  }

  private isDataFrameEnvelope(envelope: FameEnvelope): boolean {
    return Boolean(
      envelope.frame && (envelope.frame as { type?: string }).type === "Data",
    );
  }

  private hasPayload(envelope: FameEnvelope): boolean {
    const frame = envelope.frame;
    if (!frame || !("payload" in frame)) {
      return false;
    }
    const payload = frame.payload;
    return payload !== undefined && payload !== null && payload !== "";
  }

  private isDecryptableEnvelope(envelope: FameEnvelope): boolean {
    if (!this.isDataFrameEnvelope(envelope)) {
      return false;
    }

    const header = envelope.sec?.enc;
    const frame = envelope.frame;
    if (!header?.val || !frame || !("payload" in frame) || !frame.payload) {
      return false;
    }

    return header.alg === "ECDH-ES+A256GCM";
  }

  private makeJsonSerializable(value: unknown): Serializable {
    if (value === null || value === undefined) {
      return null;
    }

    if (Array.isArray(value)) {
      return value.map((item) => this.makeJsonSerializable(item));
    }

    if (typeof value === "object") {
      if (typeof (value as any).toJSON === "function") {
        return (value as any).toJSON();
      }

      if (typeof (value as any).model_dump === "function") {
        return (value as any).model_dump();
      }

      if (typeof (value as any).dict === "function") {
        return (value as any).dict();
      }

      if (
        (value as Record<string, unknown>).__proto__ ||
        Object.getPrototypeOf(value) !== Object.prototype
      ) {
        return { ...(value as Record<string, unknown>) };
      }

      return value as Record<string, unknown>;
    }

    return value as Serializable;
  }

  private decodeBase64Flexible(value: string): Uint8Array | null {
    const normalized = value.replace(/\s+/g, "");
    const candidates = [
      normalized,
      normalized.replace(/\+/g, "-").replace(/\//g, "_"),
    ];

    for (const candidate of candidates) {
      try {
        return urlsafeBase64Decode(candidate);
      } catch {
        continue;
      }
    }

    if (typeof Buffer !== "undefined") {
      try {
        return Uint8Array.from(Buffer.from(normalized, "base64"));
      } catch {
        // fall through
      }
    }

    if (typeof atob === "function") {
      try {
        const padded = normalized.padEnd(
          Math.ceil(normalized.length / 4) * 4,
          "=",
        );
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i += 1) {
          bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
      } catch {
        return null;
      }
    }

    return null;
  }

  private getRecordValue(record: KeyRecord, key: string): unknown {
    const container = record as Record<string, unknown>;
    return container[key];
  }
}
