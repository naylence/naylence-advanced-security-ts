import type { FameDeliveryContext, FameEnvelope } from "@naylence/core";
import { getLogger } from "@naylence/runtime";

import type { AFTSigner, SignAftOptions } from "./aft-signer.js";
import { createAftSigner, type CreateAftSignerOptions } from "./aft-signer.js";
import { StickinessMode } from "./stickiness-mode.js";

const logger = getLogger("naylence.fame.stickiness.aft_helper");

export interface RequestStickinessOptions {
  readonly ttlSec?: number | null;
  readonly scope?: string | null;
  readonly context?: FameDeliveryContext | null;
}

export class AFTHelper {
  public readonly signer: AFTSigner;
  public nodeSid: string;
  public readonly maxTtlSec: number;

  public constructor(options: {
    signer: AFTSigner;
    nodeSid: string;
    maxTtlSec: number;
  }) {
    this.signer = options.signer;
    this.nodeSid = options.nodeSid;
    this.maxTtlSec = options.maxTtlSec;
  }

  public async requestStickiness(
    envelope: FameEnvelope,
    options: RequestStickinessOptions = {},
  ): Promise<boolean> {
    const ttlSec = options.ttlSec ?? this.maxTtlSec;
    const scope = options.scope ?? null;
    const context = options.context ?? null;

    let clientSid: string | undefined;
    if (context?.stickySid) {
      clientSid = context.stickySid;
      logger.debug("client_sticky_sid_extracted", { client_sid: clientSid });
    }

    const signOptions: SignAftOptions = {
      sid: this.nodeSid,
      ttlSec,
      scope,
      clientSid: clientSid ?? null,
    };

    try {
      const aftToken = await this.signer.signAft(signOptions);

      if (!aftToken) {
        return false;
      }

      if (!envelope.meta) {
        envelope.meta = {};
      }

      let setMeta = envelope.meta.set as Record<string, unknown> | undefined;
      if (!setMeta || typeof setMeta !== "object") {
        setMeta = {};
        envelope.meta.set = setMeta as Record<
          string,
          string | number | boolean
        >;
      }

      (setMeta as Record<string, unknown>).aft = aftToken;

      logger.debug("aft_instruction_added", {
        envelope_id: envelope.id,
        ttl_sec: ttlSec,
        scope,
        security_level: this.signer.securityLevel,
      });

      return true;
    } catch (error) {
      logger.error("aft_generation_failed", {
        envelope_id: envelope.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  public requestNodeStickiness(
    envelope: FameEnvelope,
    options: Omit<RequestStickinessOptions, "scope"> = {},
  ): Promise<boolean> {
    return this.requestStickiness(envelope, { ...options, scope: "node" });
  }

  public requestFlowStickiness(
    envelope: FameEnvelope,
    options: Omit<RequestStickinessOptions, "scope"> = {},
  ): Promise<boolean> {
    return this.requestStickiness(envelope, { ...options, scope: "flow" });
  }

  public requestSessionStickiness(
    envelope: FameEnvelope,
    options: Omit<RequestStickinessOptions, "scope"> = {},
  ): Promise<boolean> {
    return this.requestStickiness(envelope, { ...options, scope: "sess" });
  }
}

export interface CreateAftHelperOptions extends CreateAftSignerOptions {
  nodeSid: string;
}

export function createAftHelper(options: CreateAftHelperOptions): AFTHelper {
  const { nodeSid, maxTtlSec = 7200 } = options;
  const signer = createAftSigner(options);
  return new AFTHelper({ signer, nodeSid, maxTtlSec });
}

export const DEFAULT_STICKINESS_SECURITY_LEVEL = StickinessMode.SIGNED_OPTIONAL;
