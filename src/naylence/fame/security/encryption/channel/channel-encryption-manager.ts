import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import {
  type DataFrame,
  type EncryptionHeader,
  type SecurityHeader,
  type FameEnvelope,
  type FameDeliveryContext,
  type DeliveryAckFrame,
  type SecureOpenFrame,
  FameAddress,
  formatAddress,
  localDeliveryContext,
} from "@naylence/core";
import {
  EncryptionResult,
  type EncryptionManager,
  type EncryptionOptions,
} from "@naylence/runtime";
import type {
  SecureChannelManager,
  SecureChannelState,
} from "@naylence/runtime";
import { requireCryptoSupport } from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";
import { TaskSpawner } from "@naylence/runtime";
import type { NodeLike } from "@naylence/runtime";
import { generateId } from "@naylence/core";
import { urlsafeBase64Decode } from "@naylence/runtime";

const logger = getLogger(
  "naylence.fame.security.encryption.channel.channel_encryption_manager",
);

const SUPPORTED_CHANNEL_ALGORITHMS = ["chacha20-poly1305-channel"] as const;
const CHANNEL_ENCRYPTION_ALGORITHM = "chacha20-poly1305-channel";
const HANDSHAKE_ALGORITHM = "CHACHA20P1305";
const SYSTEM_INBOX = "__sys__";
const NONCE_LENGTH = 12;

type TaskSpawnerLike = Pick<TaskSpawner, "spawn">;

function isTaskSpawnerLike(value: unknown): value is TaskSpawnerLike {
  return Boolean(
    value && typeof (value as TaskSpawnerLike).spawn === "function",
  );
}

function toUint8Array(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof ArrayBuffer !== "undefined") {
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      const view = value as ArrayBufferView;
      return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    }
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value);
  }
  return null;
}

function encodeBase64(data: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(data).toString("base64");
  }

  let binary = "";
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  if (typeof btoa === "function") {
    return btoa(binary);
  }
  throw new Error("Base64 encoding not supported in this environment");
}

function decodeBase64(encoded: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(encoded, "base64"));
  }
  if (typeof atob === "function") {
    const binary = atob(encoded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  throw new Error("Base64 decoding not supported in this environment");
}

function randomBytes(length: number): Uint8Array {
  if (
    typeof crypto !== "undefined" &&
    typeof crypto.getRandomValues === "function"
  ) {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return buffer;
  }

  try {
    const { randomBytes: nodeRandomBytes } =
      require("node:crypto") as typeof import("node:crypto");
    return nodeRandomBytes(length);
  } catch {
    throw new Error(
      "Crypto random bytes are not available in this environment",
    );
  }
}

function toFameAddress(
  value: FameAddress | string | null | undefined,
): FameAddress | null {
  if (!value) {
    return null;
  }

  if (value instanceof FameAddress) {
    return value;
  }

  return new FameAddress(String(value));
}

function toDestinationString(
  value: FameAddress | string | null | undefined,
): string | null {
  if (!value) {
    return null;
  }
  if (value instanceof FameAddress) {
    return value.toString();
  }
  if (typeof value === "string") {
    return value;
  }
  return null;
}

function makeJsonSerializable(value: unknown): unknown {
  if (value === null || value === undefined) {
    return null;
  }

  if (Array.isArray(value)) {
    return value.map((item) => makeJsonSerializable(item));
  }

  if (value instanceof Uint8Array) {
    return Array.from(value);
  }

  if (typeof value === "object") {
    const candidate = value as Record<string, unknown> & {
      toJSON?: () => unknown;
      model_dump?: () => unknown;
      dict?: () => unknown;
    };

    if (typeof candidate.toJSON === "function") {
      return candidate.toJSON();
    }

    if (typeof candidate.model_dump === "function") {
      return candidate.model_dump();
    }

    if (typeof candidate.dict === "function") {
      return candidate.dict();
    }

    return { ...candidate };
  }

  return value;
}

export interface ChannelEncryptionManagerDependencies {
  readonly secureChannelManager?: SecureChannelManager | null;
  readonly nodeLike?: NodeLike | null;
  readonly taskSpawner?: TaskSpawnerLike | null;
}

export class ChannelEncryptionManager implements EncryptionManager {
  private readonly secureChannelManager?: SecureChannelManager | null;
  private readonly nodeLike?: NodeLike | null;
  private readonly taskSpawner: TaskSpawnerLike | null;
  private readonly pendingEnvelopes = new Map<string, FameEnvelope[]>();
  private readonly handshakeInProgress = new Set<string>();
  private readonly addrChannelMap = new Map<string, string>();

  constructor({
    secureChannelManager = null,
    nodeLike = null,
    taskSpawner = null,
  }: ChannelEncryptionManagerDependencies = {}) {
    this.secureChannelManager = secureChannelManager ?? null;
    this.nodeLike = nodeLike ?? null;
    this.taskSpawner =
      taskSpawner ?? (isTaskSpawnerLike(nodeLike) ? nodeLike : taskSpawner);
  }

  public async encryptEnvelope(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null = null,
  ): Promise<EncryptionResult> {
    const frame = envelope.frame;
    if (!this.isDataFrame(frame)) {
      return EncryptionResult.skipped(envelope);
    }

    if (frame.payload === null || typeof frame.payload === "undefined") {
      return EncryptionResult.skipped(envelope);
    }

    const destination = opts?.destination ?? envelope.to ?? null;
    const destinationStr = toDestinationString(destination);

    if (!destinationStr) {
      logger.warning("no_destination_for_channel_encryption", {
        envelope_id: envelope.id,
      });
      return EncryptionResult.skipped(envelope);
    }

    if (!this.secureChannelManager) {
      logger.warning("no_secure_channel_manager_available", {
        envelope_id: envelope.id,
      });
      return EncryptionResult.skipped(envelope);
    }

    const existingChannelId = this.findExistingChannel(destinationStr);
    if (existingChannelId) {
      try {
        return this.encryptWithChannel(envelope, existingChannelId);
      } catch (error) {
        logger.error("channel_encryption_failed", {
          error: error instanceof Error ? error.message : String(error),
          channel_id: existingChannelId,
        });
        return EncryptionResult.skipped(envelope);
      }
    }

    await this.queueAndInitiateHandshake(
      envelope,
      destination,
      destinationStr,
      opts ?? null,
    );
    return EncryptionResult.queued();
  }

  public async decryptEnvelope(
    envelope: FameEnvelope,
    opts: EncryptionOptions | null = null,
  ): Promise<FameEnvelope> {
    void opts;
    requireCryptoSupport();

    const frame = envelope.frame;
    if (
      !this.isDataFrame(frame) ||
      frame.payload === null ||
      typeof frame.payload === "undefined"
    ) {
      return envelope;
    }

    if (!envelope.sec || !envelope.sec.enc) {
      return envelope;
    }

    const encHeader = envelope.sec.enc;
    if (!encHeader.alg || !this.isChannelAlgorithm(encHeader.alg)) {
      return envelope;
    }

    const channelId = encHeader.kid;
    if (!channelId) {
      logger.error("missing_channel_id_in_encryption_header", {
        envelope_id: envelope.id,
      });
      return envelope;
    }

    const nonce = this.decodeNonceValue(encHeader.val ?? "");
    if (!nonce) {
      logger.error("invalid_nonce_in_encryption_header", {
        envelope_id: envelope.id,
        value_present: Boolean(encHeader.val),
      });
      return envelope;
    }

    if (!this.secureChannelManager) {
      logger.warning("no_secure_channel_manager_for_decryption", {
        envelope_id: envelope.id,
      });
      return envelope;
    }

    const channelState = this.getChannelState(channelId);
    if (!channelState) {
      logger.error("channel_not_available_for_decryption", {
        channel_id: channelId,
      });
      return envelope;
    }

    const ciphertext = this.extractCiphertext(frame.payload);
    if (!ciphertext) {
      logger.error("invalid_ciphertext_payload", { envelope_id: envelope.id });
      return envelope;
    }

    try {
      const aad = new TextEncoder().encode(channelId);
      const aead = chacha20poly1305(channelState.key, nonce, aad);
      const plaintextBytes = aead.decrypt(ciphertext);

      const decodedPayload = this.deserializePayload(plaintextBytes);
      frame.payload = decodedPayload;
      frame.codec = "json";

      if (envelope.sec) {
        delete envelope.sec.enc;
        if (!envelope.sec.sig) {
          envelope.sec = undefined;
        }
      }

      if (envelope.replyTo) {
        this.addrChannelMap.set(String(envelope.replyTo), channelId);
      }

      if (envelope.sid) {
        this.addrChannelMap.set(envelope.sid, channelId);
      }

      return envelope;
    } catch (error) {
      logger.error("channel_decryption_failed", {
        channel_id: channelId,
        error: error instanceof Error ? error.message : String(error),
      });
      return envelope;
    }
  }

  public async notifyChannelEstablished(channelId: string): Promise<void> {
    logger.debug("channel_encryption_manager_notified", {
      channel_id: channelId,
      manager_type: "channel",
    });

    if (!channelId.startsWith("auto-")) {
      logger.warning("unexpected_channel_id_format", { channel_id: channelId });
      return;
    }

    const destinationStr = this.extractDestinationFromChannelId(channelId);
    if (!destinationStr) {
      logger.warning("cannot_parse_destination_from_channel_id", {
        channel_id: channelId,
      });
      return;
    }

    this.handshakeInProgress.delete(destinationStr);

    if (!this.pendingEnvelopes.has(destinationStr)) {
      logger.debug("no_pending_queue_for_destination", {
        destination: destinationStr,
      });
      return;
    }

    const queuedEnvelopes = this.pendingEnvelopes.get(destinationStr) ?? [];
    this.pendingEnvelopes.delete(destinationStr);

    if (!this.secureChannelManager) {
      logger.error("no_secure_channel_manager_for_queue_drain", {
        channel_id: channelId,
      });
      return;
    }

    for (const envelope of queuedEnvelopes) {
      try {
        const result = this.encryptWithChannel(envelope, channelId);
        if (!result.envelope) {
          logger.warning("failed_to_encrypt_queued_envelope", {
            envelope_id: envelope.id,
            channel_id: channelId,
          });
          continue;
        }

        const encryptedEnvelope = result.envelope;
        this.runAsyncTask(
          () => this.deliverEnvelope(encryptedEnvelope),
          `deliver-queued-${envelope.id}`,
        );
      } catch (error) {
        logger.error("failed_to_encrypt_queued_envelope", {
          envelope_id: envelope.id,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  public async notifyChannelFailed(
    channelId: string,
    reason: string = "handshake_failed",
  ): Promise<void> {
    logger.debug("channel_encryption_manager_notified_failure", {
      channel_id: channelId,
      reason,
    });

    if (!channelId.startsWith("auto-")) {
      logger.warning("unexpected_channel_id_format_on_failure", {
        channel_id: channelId,
      });
      return;
    }

    const destinationStr = this.extractDestinationFromChannelId(channelId);
    if (!destinationStr) {
      logger.warning("cannot_parse_destination_from_channel_id_on_failure", {
        channel_id: channelId,
      });
      return;
    }

    this.handshakeInProgress.delete(destinationStr);

    // Clear any cached channel mapping for this destination since the channel failed
    const cachedChannelId = this.addrChannelMap.get(destinationStr);
    if (cachedChannelId === channelId) {
      this.addrChannelMap.delete(destinationStr);
      logger.debug("cleared_channel_cache_for_failed_channel", {
        destination: destinationStr,
        channel_id: channelId,
      });
    }

    const queuedEnvelopes = this.pendingEnvelopes.get(destinationStr);
    if (!queuedEnvelopes || queuedEnvelopes.length === 0) {
      logger.debug("no_pending_queue_for_failed_destination", {
        destination: destinationStr,
      });
      return;
    }

    this.pendingEnvelopes.delete(destinationStr);

    for (const envelope of queuedEnvelopes) {
      await this.handleFailedEnvelope(
        envelope,
        destinationStr,
        channelId,
        reason,
      );
    }
  }

  /**
   * Clear cached channel mappings for a destination.
   * This should be called when routes are removed or channels are closed
   * to prevent using stale channel references.
   */
  public clearChannelCacheForDestination(destination: string): void {
    const cached = this.addrChannelMap.get(destination);
    if (cached) {
      this.addrChannelMap.delete(destination);
      logger.debug("cleared_channel_cache_for_destination", {
        destination,
        cached_channel_id: cached,
      });
    }
  }

  private isChannelAlgorithm(algorithm: string): boolean {
    return SUPPORTED_CHANNEL_ALGORITHMS.includes(
      algorithm as (typeof SUPPORTED_CHANNEL_ALGORITHMS)[number],
    );
  }

  private isDataFrame(frame: FameEnvelope["frame"]): frame is DataFrame {
    return Boolean(frame && (frame as DataFrame).type === "Data");
  }

  private findExistingChannel(destination: string): string | null {
    if (!this.secureChannelManager) {
      return null;
    }

    const cached = this.addrChannelMap.get(destination);
    if (cached && this.getChannelState(cached)) {
      logger.debug("using_cached_channel", { destination, channel_id: cached });
      return cached;
    }

    const channels = this.secureChannelManager.channels;
    for (const channelId of Object.keys(channels)) {
      if (channelId.startsWith(`auto-${destination}-`)) {
        this.addrChannelMap.set(destination, channelId);
        logger.debug("using_existing_channel", {
          destination,
          channel_id: channelId,
        });
        return channelId;
      }
    }

    return null;
  }

  private async queueAndInitiateHandshake(
    envelope: FameEnvelope,
    destination: FameAddress | string | null,
    destinationStr: string,
    opts: EncryptionOptions | null,
  ): Promise<void> {
    const queue = this.pendingEnvelopes.get(destinationStr) ?? [];
    queue.push(envelope);
    this.pendingEnvelopes.set(destinationStr, queue);

    logger.debug("queued_envelope_for_channel_handshake", {
      envelope_id: envelope.id,
      destination: destinationStr,
    });

    if (this.handshakeInProgress.has(destinationStr)) {
      logger.debug("handshake_already_in_progress", {
        destination: destinationStr,
      });
      return;
    }

    this.handshakeInProgress.add(destinationStr);

    const taskName = `handshake-${destinationStr}`;
    this.runAsyncTask(async () => {
      try {
        await this.initiateChannelHandshakeAsync(
          destination ?? destinationStr,
          destinationStr,
          opts,
        );
      } finally {
        this.handshakeInProgress.delete(destinationStr);
      }
    }, taskName);
  }

  private async initiateChannelHandshakeAsync(
    destination: FameAddress | string,
    destinationStr: string,
    opts: EncryptionOptions | null,
  ): Promise<void> {
    void opts;
    if (!this.secureChannelManager) {
      logger.error("no_secure_channel_manager_for_async_handshake_initiation");
      return;
    }

    const channelId = this.generateChannelId(destinationStr);

    try {
      const openFrame = this.secureChannelManager.generateOpenFrame(
        channelId,
        HANDSHAKE_ALGORITHM,
      );
      const success = await this.sendSecureOpenFrameAsync(
        openFrame,
        destination,
      );

      if (success) {
        logger.debug("sent_secure_open_frame_async", {
          channel_id: channelId,
          destination: destinationStr,
        });
      } else {
        logger.warning("failed_to_send_secure_open_frame_async", {
          channel_id: channelId,
        });
      }
    } catch (error) {
      logger.error("async_channel_handshake_initiation_failed", {
        destination: destinationStr,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  private async sendSecureOpenFrameAsync(
    openFrame: SecureOpenFrame,
    destination: FameAddress | string,
  ): Promise<boolean> {
    const node = this.nodeLike;
    if (!node) {
      logger.error("no_node_available_for_sending_secure_open_async");
      return false;
    }

    const envelopeFactory = node.envelopeFactory;
    if (!envelopeFactory) {
      logger.error("no_envelope_factory_available_for_secure_open_async");
      return false;
    }

    const replyTo = this.buildSystemReplyTo();
    if (!replyTo) {
      logger.error("no_physical_path_available_for_reply_to_async");
      return false;
    }

    const toAddress = toFameAddress(destination);
    if (!toAddress) {
      logger.error("invalid_destination_for_secure_open", {
        destination: String(destination),
      });
      return false;
    }

    const envelope = envelopeFactory.createEnvelope({
      to: toAddress,
      frame: openFrame,
      replyTo,
      corrId: generateId(),
    });

    await this.deliverEnvelope(envelope);
    logger.debug("delivered_secure_open_frame_async", {
      channel_id: openFrame.cid,
    });
    return true;
  }

  private async deliverEnvelope(envelope: FameEnvelope): Promise<void> {
    const node = this.nodeLike;
    if (!node) {
      logger.error("no_node_available_for_delivery", {
        envelope_id: envelope.id,
      });
      return;
    }

    const context: FameDeliveryContext = localDeliveryContext(
      node.sid ?? undefined,
    );
    await node.deliver(envelope, context);
  }

  private encryptWithChannel(
    envelope: FameEnvelope,
    channelId: string,
  ): EncryptionResult {
    if (!this.secureChannelManager) {
      logger.error("no_secure_channel_manager_for_encryption");
      return EncryptionResult.skipped(envelope);
    }

    const frame = envelope.frame;
    if (!this.isDataFrame(frame)) {
      logger.error("attempted_to_encrypt_non_dataframe", {
        frame_type: (frame as { type?: string }).type ?? typeof frame,
      });
      return EncryptionResult.skipped(envelope);
    }

    const channelState = this.getChannelState(channelId);
    if (!channelState) {
      logger.error("channel_not_in_channels", { channel_id: channelId });
      return EncryptionResult.skipped(envelope);
    }

    const payloadBytes = this.serializePayload(frame.payload);
    if (!payloadBytes) {
      return EncryptionResult.skipped(envelope);
    }

    const nonce = randomBytes(NONCE_LENGTH);
    const aad = new TextEncoder().encode(channelId);
    const aead = chacha20poly1305(channelState.key, nonce, aad);
    const ciphertext = aead.encrypt(payloadBytes);

    const encryptionHeader: EncryptionHeader = {
      alg: CHANNEL_ENCRYPTION_ALGORITHM,
      val: Array.from(nonce)
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join(""), // Hex encoding (Python reference)
      kid: channelId,
    };

    const encodedCiphertext = encodeBase64(ciphertext);

    frame.payload = encodedCiphertext;
    frame.codec = "b64";

    if (envelope.sec) {
      envelope.sec.enc = encryptionHeader;
    } else {
      envelope.sec = { enc: encryptionHeader } as SecurityHeader;
    }

    return EncryptionResult.ok(envelope);
  }

  private serializePayload(payload: unknown): Uint8Array | null {
    if (payload === null || typeof payload === "undefined") {
      return null;
    }

    if (payload instanceof Uint8Array) {
      return payload;
    }

    if (typeof ArrayBuffer !== "undefined") {
      if (payload instanceof ArrayBuffer || ArrayBuffer.isView(payload)) {
        return toUint8Array(payload);
      }
    }

    if (typeof payload === "string") {
      return new TextEncoder().encode(payload);
    }

    if (typeof payload === "number" || typeof payload === "boolean") {
      return new TextEncoder().encode(JSON.stringify(payload));
    }

    const serializable = makeJsonSerializable(payload);
    return new TextEncoder().encode(JSON.stringify(serializable));
  }

  private extractCiphertext(payload: unknown): Uint8Array | null {
    if (payload instanceof Uint8Array) {
      return payload;
    }

    if (typeof payload === "string") {
      try {
        return decodeBase64(payload);
      } catch (error) {
        logger.error("failed_to_decode_base64_ciphertext", {
          error: error instanceof Error ? error.message : String(error),
        });
        return null;
      }
    }

    if (
      payload instanceof ArrayBuffer ||
      ArrayBuffer.isView(payload as ArrayBufferView)
    ) {
      return toUint8Array(payload);
    }

    return null;
  }

  private deserializePayload(bytes: Uint8Array): unknown {
    const decoder = new TextDecoder();
    const decoded = decoder.decode(bytes);
    try {
      return JSON.parse(decoded);
    } catch {
      return decoded;
    }
  }

  private extractDestinationFromChannelId(channelId: string): string | null {
    const parts = channelId.split("-");
    if (parts.length < 3) {
      return null;
    }
    return parts.slice(1, -1).join("-");
  }

  private async handleFailedEnvelope(
    envelope: FameEnvelope,
    destinationStr: string,
    channelId: string,
    reason: string,
  ): Promise<void> {
    logger.warning("envelope_failed_due_to_channel_handshake_failure", {
      envelope_id: envelope.id,
      destination: destinationStr,
      channel_id: channelId,
      reason,
    });

    const frame = envelope.frame;
    if (!this.isDataFrame(frame)) {
      logger.debug("skipping_nack_for_non_dataframe", {
        envelope_id: envelope.id,
        frame_type: (frame as { type?: string }).type ?? typeof frame,
      });
      return;
    }

    if (!envelope.replyTo) {
      logger.debug("skipping_nack_no_reply_to", { envelope_id: envelope.id });
      return;
    }

    await this.sendDeliveryNack(
      envelope,
      `channel_handshake_failed: ${reason}`,
    );
  }

  private async sendDeliveryNack(
    envelope: FameEnvelope,
    failureReason: string,
  ): Promise<void> {
    const node = this.nodeLike;
    if (!node) {
      logger.error("no_node_available_for_sending_delivery_nack");
      return;
    }

    const envelopeFactory = node.envelopeFactory;
    if (!envelopeFactory) {
      logger.error("no_envelope_factory_available_for_delivery_nack");
      return;
    }

    const replyTo = toFameAddress(envelope.replyTo ?? null);
    if (!replyTo) {
      logger.error("invalid_reply_to_for_delivery_nack", {
        reply_to: envelope.replyTo,
      });
      return;
    }

    const nackFrame: DeliveryAckFrame = {
      type: "DeliveryAck",
      ok: false,
      code: "channel_handshake_failed",
      reason: failureReason,
    };

    const nackEnvelope = envelopeFactory.createEnvelope({
      to: replyTo,
      frame: nackFrame,
      corrId: envelope.corrId ?? generateId(),
    });

    await this.deliverEnvelope(nackEnvelope);
    logger.debug("delivered_delivery_nack", {
      original_envelope_id: envelope.id,
      nack_envelope_id: nackEnvelope.id,
    });
  }

  private getChannelState(channelId: string): SecureChannelState | null {
    if (!this.secureChannelManager) {
      return null;
    }
    const channelState = this.secureChannelManager.channels[channelId];
    return channelState ?? null;
  }

  private buildSystemReplyTo(): FameAddress | null {
    const node = this.nodeLike;
    if (!node) {
      return null;
    }

    const physicalPath = node.physicalPath ?? "";
    if (!physicalPath) {
      return null;
    }

    return formatAddress(SYSTEM_INBOX, physicalPath);
  }

  private generateChannelId(destinationStr: string): string {
    return `auto-${destinationStr}-${generateId()}`;
  }

  private runAsyncTask(task: () => Promise<void>, name: string): void {
    if (this.taskSpawner) {
      this.taskSpawner.spawn(
        async () => {
          await task();
        },
        { name },
      );
      return;
    }

    (async () => {
      try {
        await task();
      } catch (error) {
        logger.error("async_task_failed", {
          task_name: name,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    })().catch(() => {
      // Swallow to avoid unhandled rejection; error already logged above.
    });
  }

  private decodeNonceValue(value: string): Uint8Array | null {
    if (!value) {
      return null;
    }

    const hexCandidate = value.trim();
    if (hexCandidate.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hexCandidate)) {
      const bytes = new Uint8Array(hexCandidate.length / 2);
      for (let i = 0; i < hexCandidate.length; i += 2) {
        bytes[i / 2] = parseInt(hexCandidate.slice(i, i + 2), 16);
      }
      if (bytes.length > 0) {
        return bytes;
      }
    }

    const base64Candidates = [
      value,
      value.replace(/-/g, "+").replace(/_/g, "/"),
    ];
    for (const candidate of base64Candidates) {
      try {
        // Standard base64 decode first (Buffer), then urlsafe fallback
        if (typeof Buffer !== "undefined") {
          const decoded = Uint8Array.from(Buffer.from(candidate, "base64"));
          if (decoded.length > 0) {
            return decoded;
          }
        }
      } catch {
        // ignore and try next
      }

      try {
        const decoded = urlsafeBase64Decode(candidate);
        if (decoded.length > 0) {
          return decoded;
        }
      } catch {
        // ignore and continue
      }
    }

    return null;
  }
}
