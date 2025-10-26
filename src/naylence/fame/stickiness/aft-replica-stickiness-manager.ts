import type {
  FameDeliveryContext,
  FameEnvelope,
  Stickiness,
} from "@naylence/core";
import { DeliveryOriginType } from "@naylence/core";
import { BaseNodeEventListener } from "@naylence/runtime";
import type { NodeLike } from "@naylence/runtime";
import { getLogger } from "@naylence/runtime";

import type { AFTHelper } from "./aft-helper.js";
import {
  createAftHelper,
  DEFAULT_STICKINESS_SECURITY_LEVEL,
} from "./aft-helper.js";
import type { AFTSigner } from "./aft-signer.js";
import { StickinessMode, normalizeStickinessMode } from "./stickiness-mode.js";
import type { ReplicaStickinessManager } from "@naylence/runtime";

const logger = getLogger(
  "naylence.fame.stickiness.aft_replica_stickiness_manager",
);

type StickinessAwareContext = FameDeliveryContext & {
  stickinessRequired?: boolean | null;
  stickiness_required?: boolean | null;
  stickySid?: string | null;
  sticky_sid?: string | null;
};

function isStickinessRequired(context: StickinessAwareContext): boolean {
  if (typeof context.stickinessRequired === "boolean") {
    return context.stickinessRequired;
  }
  if (typeof context.stickiness_required === "boolean") {
    return context.stickiness_required;
  }
  return false;
}

export interface AFTReplicaStickinessManagerOptions {
  securityLevel?: StickinessMode | string | null;
  aftHelper?: AFTHelper | null;
  maxTtlSec?: number | null;
}

export class AFTReplicaStickinessManager
  extends BaseNodeEventListener
  implements ReplicaStickinessManager
{
  private readonly securityLevel: StickinessMode;
  private aftHelper: AFTHelper | null;
  private readonly maxTtlSec: number;
  private isInitialized: boolean;
  private negotiatedStickiness: Stickiness | null;

  public constructor(options: AFTReplicaStickinessManagerOptions = {}) {
    super();
    this.securityLevel =
      normalizeStickinessMode(
        options.securityLevel ?? DEFAULT_STICKINESS_SECURITY_LEVEL,
      ) ?? DEFAULT_STICKINESS_SECURITY_LEVEL;
    this.aftHelper = options.aftHelper ?? null;
    this.maxTtlSec = options.maxTtlSec ?? 7200;
    this.isInitialized = this.aftHelper !== null;
    this.negotiatedStickiness = null;

    if (this.aftHelper) {
      logger.debug("aft_replica_stickiness_manager_initialized", {
        helper_type: this.aftHelper.signer.constructor.name,
        security_level: this.aftHelper.signer.securityLevel,
        max_ttl_sec: this.aftHelper.maxTtlSec,
      });
    } else {
      logger.debug("aft_replica_stickiness_manager_created", {
        security_level: this.securityLevel,
        max_ttl_sec: this.maxTtlSec,
      });
    }
  }

  public offer(): Stickiness | null {
    return { mode: "aft", supportedModes: ["aft", "attr"], version: 1 };
  }

  public accept(stickiness: Stickiness | null): void {
    this.negotiatedStickiness = stickiness ?? null;
    logger.debug("replica_stickiness_policy_set", {
      enabled: stickiness?.enabled ?? null,
      mode: stickiness?.mode ?? null,
      ttl: stickiness?.ttlSec ?? null,
    });
  }

  public async onForwardUpstream(
    _node: NodeLike,
    envelope: FameEnvelope,
    context?: FameDeliveryContext,
  ): Promise<FameEnvelope | null> {
    if (!context) {
      return envelope;
    }

    const helper = this.aftHelper;
    if (!helper) {
      logger.debug("aft_helper_not_ready_skip_injection", {
        envelope_id: envelope.id,
        delivery_origin: context.originType ?? null,
        reason: "not_initialized",
      });
      return envelope;
    }

    const stickinessContext = context as StickinessAwareContext;

    if (
      isStickinessRequired(stickinessContext) &&
      context.originType === DeliveryOriginType.LOCAL
    ) {
      if (this.negotiatedStickiness) {
        const negotiated = this.negotiatedStickiness;
        if (
          negotiated.enabled === false ||
          (negotiated.mode !== null &&
            negotiated.mode !== undefined &&
            negotiated.mode !== "aft")
        ) {
          logger.debug("aft_injection_skipped_due_to_policy", {
            envelope_id: envelope.id,
            policy_mode: negotiated.mode ?? null,
            policy_enabled: negotiated.enabled ?? null,
          });
          return envelope;
        }
      }

      logger.debug("applying_aft_for_upstream_stickiness_required", {
        envelope_id: envelope.id,
        from_system_id: context.fromSystemId ?? null,
        delivery_origin: context.originType ?? null,
      });

      const success = await helper.requestStickiness(envelope, {
        ttlSec: null,
        scope: "node",
        context: stickinessContext,
      });

      if (success) {
        logger.debug("aft_token_applied_via_context_flag_upstream", {
          envelope_id: envelope.id,
          from_system_id: context.fromSystemId ?? null,
          delivery_origin: context.originType ?? null,
        });
      } else {
        logger.debug("aft_token_not_applied_upstream", {
          envelope_id: envelope.id,
          delivery_origin: context.originType ?? null,
          reason: "helper_returned_false",
        });
      }
    }

    return envelope;
  }

  public async onNodeStarted(node: NodeLike): Promise<void> {
    if (!this.isInitialized) {
      await this.initializeAftHelper(node);
      return;
    }

    if (this.aftHelper && node.sid) {
      this.updateNodeSid(node.sid);
      logger.debug("aft_replica_stickiness_manager_sid_updated", {
        node_id: node.id ?? "unknown",
        node_sid: node.sid,
        security_level: this.aftHelper.signer.securityLevel,
      });
    } else if (!node.sid) {
      logger.warning("aft_replica_stickiness_manager_no_sid_available", {
        node_id: node.id ?? "unknown",
      });
    } else {
      logger.error("aft_replica_stickiness_manager_node_missing_sid", {
        node_type: node.constructor?.name ?? typeof node,
      });
    }
  }

  public updateNodeSid(nodeSid: string): void {
    if (this.aftHelper) {
      this.aftHelper.nodeSid = nodeSid;
      logger.debug("aft_replica_stickiness_manager_sid_updated", {
        new_sid: nodeSid,
      });
    }
  }

  private async initializeAftHelper(node: NodeLike): Promise<void> {
    const nodeSid = node.sid;
    if (!nodeSid) {
      logger.error("aft_replica_stickiness_manager_cannot_initialize_no_sid", {
        node_id: node.id ?? "unknown",
      });
      return;
    }

    const cryptoProvider = node.cryptoProvider ?? null;
    if (!cryptoProvider) {
      logger.error(
        "aft_replica_stickiness_manager_cannot_initialize_no_crypto_provider",
        {
          node_id: node.id ?? "unknown",
        },
      );
      return;
    }

    const keyId =
      typeof cryptoProvider.signatureKeyId === "string" &&
      cryptoProvider.signatureKeyId.length > 0
        ? cryptoProvider.signatureKeyId
        : "default-key-id";
    const privateKeyPem =
      typeof cryptoProvider.signingPrivatePem === "string"
        ? cryptoProvider.signingPrivatePem
        : null;

    if (this.securityLevel === StickinessMode.STRICT && !privateKeyPem) {
      logger.error("aft_replica_stickiness_manager_initialization_failed", {
        node_id: node.id ?? "unknown",
        error: "Missing signing private key for strict security level",
      });
      return;
    }

    try {
      const helper = createAftHelper({
        securityLevel: this.securityLevel,
        nodeSid,
        kid: keyId,
        privateKeyPem,
        maxTtlSec: this.maxTtlSec,
      });
      this.aftHelper = helper;
      this.isInitialized = true;

      logger.debug("aft_replica_stickiness_manager_initialized", {
        node_id: node.id ?? "unknown",
        node_sid: nodeSid,
        key_id: keyId,
        security_level: helper.signer.securityLevel,
      });
    } catch (error) {
      logger.error("aft_replica_stickiness_manager_initialization_failed", {
        node_id: node.id ?? "unknown",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  public get signer(): AFTSigner | null {
    return this.aftHelper?.signer ?? null;
  }

  public getHelper(): AFTHelper | null {
    return this.aftHelper;
  }
}

export function createAftReplicaStickinessManager(
  aftHelper: AFTHelper,
): AFTReplicaStickinessManager {
  return new AFTReplicaStickinessManager({ aftHelper });
}

export default AFTReplicaStickinessManager;
