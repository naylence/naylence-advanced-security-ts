import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type {
  DataFrame,
  SecureAcceptFrame,
  SecureCloseFrame,
  SecureOpenFrame,
} from "naylence-core";
import {
    requireCryptoSupport,
    getLogger,
} from "naylence-runtime";
import type {
    SecureChannelManager,
    SecureChannelState,
} from "naylence-runtime";

const logger = getLogger("naylence.advanced.encryption.default-channel");

const DEFAULT_ALGORITHM = "CHACHA20P1305";
const CHANNEL_KEY_LENGTH = 32;
const NONCE_PREFIX_LENGTH = 4;
const ZERO_EPHEMERAL_KEY = new Uint8Array(32);
const ZERO_EPHEMERAL_KEY_BASE64 = encodeBase64(ZERO_EPHEMERAL_KEY);

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

interface ChannelStateOptions {
  readonly key: Uint8Array;
  readonly algorithm: string;
}

type EphemeralPrivateKey = Uint8Array;

export interface DefaultSecureChannelManagerOptions {
  readonly channelTtlSeconds?: number;
}

export class DefaultSecureChannelManager implements SecureChannelManager {
  private readonly channelsMap = new Map<string, SecureChannelState>();
  private readonly ephemeralKeys = new Map<string, EphemeralPrivateKey>();
  private readonly channelTtlSeconds: number;

  constructor(options: DefaultSecureChannelManagerOptions = {}) {
    this.channelTtlSeconds = options.channelTtlSeconds ?? 3600;
  }

  public get channels(): Readonly<Record<string, SecureChannelState>> {
    return Object.freeze(Object.fromEntries(this.channelsMap.entries()));
  }

  public generateOpenFrame(channelId: string, algorithm: string = DEFAULT_ALGORITHM): SecureOpenFrame {
    requireCryptoSupport();

    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.scalarMultBase(privateKey);
    this.ephemeralKeys.set(channelId, privateKey);

    logger.debug("generated_channel_open", { cid: channelId, algorithm });

    return {
      type: "SecureOpen",
      cid: channelId,
      ephPub: encodeBase64(publicKey),
      alg: algorithm,
      opts: 0,
    } satisfies SecureOpenFrame;
  }

  public async handleOpenFrame(frame: SecureOpenFrame): Promise<SecureAcceptFrame> {
    requireCryptoSupport();

    const algorithm = frame.alg || DEFAULT_ALGORITHM;
    if (!this.isSupportedAlgorithm(algorithm)) {
      logger.warning("unsupported_channel_algorithm", { cid: frame.cid, alg: algorithm });
      return {
        type: "SecureAccept",
        cid: frame.cid,
        ok: false,
        reason: `Unsupported algorithm: ${algorithm}`,
        ephPub: ZERO_EPHEMERAL_KEY_BASE64,
        alg: algorithm,
      } satisfies SecureAcceptFrame;
    }

    let peerPublicKey: Uint8Array;
    try {
      peerPublicKey = decodeBase64(frame.ephPub);
    } catch (error) {
      logger.warning("invalid_peer_public_key", {
        cid: frame.cid,
        error: error instanceof Error ? error.message : String(error),
      });
      return {
        type: "SecureAccept",
        cid: frame.cid,
        ok: false,
        reason: "Invalid peer public key",
        ephPub: ZERO_EPHEMERAL_KEY_BASE64,
        alg: algorithm,
      } satisfies SecureAcceptFrame;
    }

    const myPrivateKey = x25519.utils.randomSecretKey();
    const myPublicKey = x25519.scalarMultBase(myPrivateKey);
    const sharedSecret = x25519.scalarMult(myPrivateKey, peerPublicKey);

    const channelKey = this.deriveChannelKey(frame.cid, sharedSecret);
  const channelState = this.createChannelState({ key: channelKey, algorithm });
    this.channelsMap.set(frame.cid, channelState);

    logger.debug("channel_established", { cid: frame.cid, algorithm });

    myPrivateKey.fill(0);
    sharedSecret.fill(0);

    return {
      type: "SecureAccept",
      cid: frame.cid,
      ok: true,
      ephPub: encodeBase64(myPublicKey),
      alg: algorithm,
    } satisfies SecureAcceptFrame;
  }

  public async handleAcceptFrame(frame: SecureAcceptFrame): Promise<boolean> {
    requireCryptoSupport();

    if (frame.ok === false) {
      logger.warning("channel_rejected", { cid: frame.cid, error: frame.reason });
      this.cleanupEphemeralKey(frame.cid);
      return false;
    }

    const privateKey = this.ephemeralKeys.get(frame.cid);
    if (!privateKey) {
      logger.error("no_ephemeral_key", { cid: frame.cid });
      return false;
    }

    let peerPublicKey: Uint8Array;
    try {
      peerPublicKey = decodeBase64(frame.ephPub);
    } catch (error) {
      logger.warning("invalid_accept_public_key", {
        cid: frame.cid,
        error: error instanceof Error ? error.message : String(error),
      });
      this.cleanupEphemeralKey(frame.cid);
      return false;
    }

    const sharedSecret = x25519.scalarMult(privateKey, peerPublicKey);
    const algorithm = frame.alg || DEFAULT_ALGORITHM;
    const channelKey = this.deriveChannelKey(frame.cid, sharedSecret);
  const channelState = this.createChannelState({ key: channelKey, algorithm });
    this.channelsMap.set(frame.cid, channelState);

    logger.debug("channel_completed", { cid: frame.cid, algorithm });

    sharedSecret.fill(0);
    this.cleanupEphemeralKey(frame.cid);

    return true;
  }

  public handleCloseFrame(frame: SecureCloseFrame): void {
    if (this.channelsMap.delete(frame.cid)) {
      logger.debug("channel_closed", { cid: frame.cid, reason: frame.reason });
    } else {
      logger.warning("close_unknown_channel", { cid: frame.cid });
    }

    this.cleanupEphemeralKey(frame.cid);
  }

  public isChannelEncrypted(frame: DataFrame): boolean {
    return Boolean(frame.cid && frame.nonce);
  }

  public hasChannel(channelId: string): boolean {
    return this.channelsMap.has(channelId);
  }

  public getChannelInfo(channelId: string): Record<string, unknown> | null {
    const state = this.channelsMap.get(channelId);
    if (!state) {
      return null;
    }

    const now = this.currentTimeSeconds();
    return {
      cid: channelId,
      algorithm: state.algorithm,
      send_counter: state.sendCounter,
      recv_counter: state.receiveCounter,
      expires_at: state.expiresAt,
      expired: now > state.expiresAt,
    };
  }

  public closeChannel(channelId: string, reason: string = "User requested"): SecureCloseFrame {
    if (this.channelsMap.delete(channelId)) {
      logger.debug("channel_closed_by_user", { cid: channelId, reason });
    }

    this.cleanupEphemeralKey(channelId);

    return {
      type: "SecureClose",
      cid: channelId,
      reason,
    } satisfies SecureCloseFrame;
  }

  public cleanupExpiredChannels(): number {
    const now = this.currentTimeSeconds();
    let removed = 0;

    for (const [channelId, state] of this.channelsMap.entries()) {
      if (now > state.expiresAt) {
        this.channelsMap.delete(channelId);
        this.cleanupEphemeralKey(channelId);
        removed += 1;
        logger.debug("channel_expired_cleanup", { cid: channelId });
      }
    }

    return removed;
  }

  public addChannel(channelId: string, channelState: SecureChannelState): void {
    this.channelsMap.set(channelId, channelState);
  }

  public removeChannel(channelId: string): boolean {
    const removed = this.channelsMap.delete(channelId);
    if (removed) {
      this.cleanupEphemeralKey(channelId);
    }
    return removed;
  }

  private isSupportedAlgorithm(algorithm: string): boolean {
    return algorithm === DEFAULT_ALGORITHM;
  }

  private deriveChannelKey(channelId: string, sharedSecret: Uint8Array): Uint8Array {
    const info = utf8ToBytes(`fame-channel:${channelId}`);
    return hkdf(sha256, sharedSecret, undefined, info, CHANNEL_KEY_LENGTH);
  }

  private createChannelState({ key, algorithm }: ChannelStateOptions): SecureChannelState {
    return {
      key,
      sendCounter: 0,
      receiveCounter: 0,
      noncePrefix: randomBytes(NONCE_PREFIX_LENGTH),
      expiresAt: this.currentTimeSeconds() + this.channelTtlSeconds,
      algorithm,
    } satisfies SecureChannelState;
  }

  private cleanupEphemeralKey(channelId: string): void {
    const key = this.ephemeralKeys.get(channelId);
    if (key) {
      key.fill(0);
      this.ephemeralKeys.delete(channelId);
    }
  }

  private currentTimeSeconds(): number {
    return Date.now() / 1000;
  }
}
