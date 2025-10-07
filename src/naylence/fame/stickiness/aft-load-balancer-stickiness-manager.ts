import type { FameDeliveryContext, FameEnvelope, Stickiness } from "naylence-core";
import { DeliveryOriginType } from "naylence-core";
import { BaseNodeEventListener } from "naylence-runtime";
import type { NodeLike } from "naylence-runtime";
import { getLogger } from "naylence-runtime";

import type { LoadBalancerStickinessManager } from "naylence-runtime";

import type { AFTLoadBalancerStickinessManagerConfig } from "./aft-load-balancer-stickiness-manager-factory.js";
import type { AFTVerifier } from "./aft-verifier.js";
import { StickinessMode } from "./stickiness-mode.js";

const logger = getLogger("naylence.advanced.stickiness.aft-load-balancer");

type Metrics = {
  cacheHits: number;
  cacheMisses: number;
  verifyFailures: number;
  associationsCreated: number;
  associationsExpired: number;
};


class AFTAssociation {
  public readonly replicaId: string;
  public readonly token: string;
  public readonly sid: string;
  public readonly exp: number;
  public readonly trustLevel: string;
  public readonly scope?: string | null;
  public readonly clientSid?: string | null;
  public readonly createdAt: number;

  public constructor(params: {
    replicaId: string;
    token: string;
    sid: string;
    exp: number;
    trustLevel: string;
    scope?: string | null;
    clientSid?: string | null;
    createdAt?: number;
  }) {
    this.replicaId = params.replicaId;
    this.token = params.token;
    this.sid = params.sid;
    this.exp = params.exp;
    this.trustLevel = params.trustLevel;
    this.scope = params.scope ?? null;
    this.clientSid = params.clientSid ?? null;
    this.createdAt = params.createdAt ?? Math.floor(Date.now() / 1000);
  }

  public isExpired(referenceTime: number = Math.floor(Date.now() / 1000)): boolean {
    return referenceTime >= this.exp;
  }

  public isLowTrust(): boolean {
    return this.trustLevel === "low-trust";
  }
}

export class AFTLoadBalancerStickinessManager
  extends BaseNodeEventListener
  implements LoadBalancerStickinessManager
{
  private readonly config: AFTLoadBalancerStickinessManagerConfig;
  private readonly verifier: AFTVerifier;

  private readonly aftAssociations = new Map<string, AFTAssociation>();
  private readonly sidCache = new Map<string, string>();
  private readonly metrics: Metrics = {
    cacheHits: 0,
    cacheMisses: 0,
    verifyFailures: 0,
    associationsCreated: 0,
    associationsExpired: 0,
  };

  private get cacheMax(): number {
    return this.config.cacheMax ?? 100_000;
  }

  private get defaultTtlSec(): number {
    return this.config.defaultTtlSec ?? 30;
  }

  public constructor(config: AFTLoadBalancerStickinessManagerConfig, verifier: AFTVerifier) {
    super();
    this.config = config;
    this.verifier = verifier;

    logger.debug("stickiness_manager_initialized", {
      enabled: this.config.enabled,
      security_level: this.config.securityLevel,
      verifier_type: verifier.constructor.name,
      default_ttl: this.defaultTtlSec,
      cache_max: this.cacheMax,
      client_echo: this.config.clientEcho,
    });
  }

  public get hasStickiness(): boolean {
    return Boolean(this.config.enabled);
  }

  public getSidCache(): ReadonlyMap<string, string> {
    return this.sidCache;
  }

  public negotiate(stickiness?: Stickiness | null): Stickiness | null {
    if (!stickiness) {
      if (this.config.enabled) {
        logger.debug("stickiness_negotiated_no_offer_attr_fallback");
        return { enabled: true, mode: "attr", version: 1 };
      }
      return null;
    }

    const version = stickiness.version ?? 1;

    if (!this.config.enabled) {
      logger.debug("stickiness_negotiation_disabled_by_config");
      return { enabled: false, version };
    }

    const childModes = new Set<string>();
    if (Array.isArray(stickiness.supportedModes) && stickiness.supportedModes.length > 0) {
      for (const mode of stickiness.supportedModes) {
        childModes.add(mode);
      }
    } else if (stickiness.mode) {
      childModes.add(stickiness.mode);
    }

    if (childModes.has("aft") && this.verifier) {
      const ttl = this.defaultTtlSec;
      const policy: Stickiness = { enabled: true, mode: "aft", ttlSec: ttl, version };
      logger.debug("stickiness_negotiated", { mode: policy.mode, ttl });
      return policy;
    }

    if (childModes.has("attr")) {
      const policy: Stickiness = { enabled: true, mode: "attr", version };
      logger.debug("stickiness_negotiated", { mode: policy.mode });
      return policy;
    }

    logger.debug("stickiness_negotiation_no_common_mode");
    return { enabled: false, version };
  }

  public async handleOutboundEnvelope(envelope: FameEnvelope, replicaId: string): Promise<string | null> {
    if (!this.config.enabled) {
      logger.debug("stickiness_disabled", { envelope_id: envelope.id });
      return null;
    }

    const aftToken = extractAftInstruction(envelope);

    if (!aftToken) {
      logger.debug("no_aft_instruction", {
        envelope_id: envelope.id,
        has_meta: Boolean(envelope.meta),
      });
      return null;
    }

    if (typeof aftToken !== "string") {
      logger.warning("invalid_aft_instruction", {
        envelope_id: envelope.id,
        replica_id: replicaId,
        reason: "set.aft value is not a string",
      });
      return null;
    }

    const verification = await this.verifier.verify(aftToken, envelope.sid ?? undefined);

    if (!verification.valid) {
      this.metrics.verifyFailures += 1;
      logger.warning("aft_verification_failed", {
        envelope_id: envelope.id,
        replica_id: replicaId,
        error: verification.error,
      });
      return null;
    }

    this.storeAssociation(aftToken, {
      replicaId,
      token: aftToken,
      sid: verification.sid ?? "",
      exp: verification.exp ?? Math.floor(Date.now() / 1000) + this.defaultTtlSec,
      trustLevel: verification.trustLevel,
      scope: verification.scope ?? null,
      clientSid: verification.clientSid ?? null,
    });

    if (verification.clientSid) {
      this.sidCache.set(verification.clientSid, replicaId);
      logger.debug("sid_cache_updated", {
        envelope_id: envelope.id,
        client_sid: verification.clientSid,
        replica_id: replicaId,
      });
    }

    this.metrics.associationsCreated += 1;

    logger.debug("aft_association_created", {
      envelope_id: envelope.id,
      replica_id: replicaId,
      sid: verification.sid,
      exp: verification.exp,
      trust_level: verification.trustLevel,
      scope: verification.scope,
    });

    return this.config.clientEcho ? aftToken : null;
  }

  public getStickyReplicaSegment(
    envelope: FameEnvelope,
    segments?: readonly string[] | null
  ): string | null {
    if (!this.config.enabled) {
      logger.debug("stickiness_disabled", { envelope_id: envelope.id });
      return null;
    }

    if (envelope.aft) {
      const replicaId = this.routeByAft(envelope.aft, envelope);
      if (replicaId) {
        this.metrics.cacheHits += 1;
        logger.debug("aft_routed_envelope", {
          envelope_id: envelope.id,
          replica_id: replicaId,
          routing_type: "aft_direct",
        });
        return replicaId;
      }
    }

    if (envelope.sid) {
      const cachedReplica = this.sidCache.get(envelope.sid);
      if (cachedReplica) {
        if (this.config.securityLevel === StickinessMode.SID_ONLY) {
          this.metrics.cacheHits += 1;
          logger.debug("sid_cache_routed_envelope", {
            envelope_id: envelope.id,
            replica_id: cachedReplica,
            sid: envelope.sid,
            routing_type: "sid_only",
          });
          return cachedReplica;
        }

        for (const [token, association] of this.aftAssociations.entries()) {
          if (association.replicaId === cachedReplica && !association.isExpired()) {
            envelope.aft = token;
            this.metrics.cacheHits += 1;
            logger.debug("sid_cache_routed_envelope", {
              envelope_id: envelope.id,
              replica_id: cachedReplica,
              sid: envelope.sid,
              routing_type: "sid_cache_with_aft",
            });
            return cachedReplica;
          }
        }

        this.metrics.cacheHits += 1;
        logger.debug("sid_cache_routed_envelope", {
          envelope_id: envelope.id,
          replica_id: cachedReplica,
          sid: envelope.sid,
          routing_type: "sid_cache_direct",
        });
        return cachedReplica;
      }

      logger.debug("no_cached_replica_for_sid", {
        envelope_id: envelope.id,
        sid: envelope.sid,
      });
    }

    if (envelope.sid && Array.isArray(segments) && segments.length > 0) {
      const index = computeDeterministicIndex(envelope.sid, segments.length);
      const chosen = segments[index];
      this.metrics.cacheHits += 1;
      logger.debug("sid_based_deterministic_choice", {
        envelope_id: envelope.id,
        sid: envelope.sid,
        chosen,
        routing_type: "sid_deterministic",
      });
      return chosen;
    }

    this.metrics.cacheMisses += 1;
    logger.debug("no_stickiness_routing", {
      envelope_id: envelope.id,
      has_aft: Boolean(envelope.aft),
      has_sid: Boolean(envelope.sid),
    });
    return null;
  }

  public cleanupExpiredAssociations(): void {
    const now = Math.floor(Date.now() / 1000);
    const expiredTokens: string[] = [];

    for (const [token, association] of this.aftAssociations.entries()) {
      if (association.isExpired(now)) {
        expiredTokens.push(token);
      }
    }

    for (const token of expiredTokens) {
      this.removeAssociation(token);
    }

    if (expiredTokens.length > 0) {
      this.metrics.associationsExpired += expiredTokens.length;
      logger.debug("cleaned_expired_associations", { count: expiredTokens.length });
    }
  }

  public replicaLeft(replicaId: string): void {
    const tokensToRemove: string[] = [];
    for (const [token, association] of this.aftAssociations.entries()) {
      if (association.replicaId === replicaId) {
        tokensToRemove.push(token);
      }
    }

    for (const token of tokensToRemove) {
      this.removeAssociation(token);
    }

    if (tokensToRemove.length > 0) {
      logger.debug("removed_associations_for_departed_replica", {
        replica_id: replicaId,
        count: tokensToRemove.length,
      });
    }
  }

  public handleReplicaLeft(replicaId: string): void {
    this.replicaLeft(replicaId);
    logger.debug("stickiness_replica_cleanup", { replica_id: replicaId });
  }

  public getMetrics(): Record<string, number> {
    return {
      ...this.metrics,
      cacheSize: this.aftAssociations.size,
      sidCacheSize: this.sidCache.size,
    };
  }

  public getAssociations(): Record<string, Record<string, unknown>> {
    const result: Record<string, Record<string, unknown>> = {};
    for (const [token, association] of this.aftAssociations.entries()) {
      result[token] = {
        replica_id: association.replicaId,
        sid: association.sid,
        client_sid: association.clientSid,
        exp: association.exp,
        trust_level: association.trustLevel,
        scope: association.scope,
        created_at: association.createdAt,
        expired: association.isExpired(),
      };
    }
    return result;
  }

  public getStickinessMetrics(): Record<string, number> {
    return this.getMetrics();
  }

  public logMetrics(): void {
    const hits = this.metrics.cacheHits;
    const misses = this.metrics.cacheMisses;
    const total = hits + misses;
    const hitRate = total > 0 ? Math.round((hits / total) * 10000) / 100 : 0;

    logger.info("stickiness_metrics_report", {
      enabled: this.config.enabled,
      security_level: this.config.securityLevel,
      cache_hits: hits,
      cache_misses: misses,
      verify_failures: this.metrics.verifyFailures,
      associations_created: this.metrics.associationsCreated,
      associations_expired: this.metrics.associationsExpired,
      active_associations: this.aftAssociations.size,
      sid_cache_entries: this.sidCache.size,
      hit_rate: hitRate,
    });
  }

  public async onDeliver(
    _node: NodeLike,
    envelope: FameEnvelope,
    context?: FameDeliveryContext
  ): Promise<FameEnvelope | null> {
    logger.debug("stickiness_manager_on_deliver", {
      envelope_id: envelope.id,
      origin_type: context?.originType ?? "unknown",
      from_system_id: context?.fromSystemId ?? null,
    });

    if (context?.originType === DeliveryOriginType.DOWNSTREAM) {
      const sourceRoute = context.fromSystemId;

      if (sourceRoute) {
        logger.debug("processing_downstream_envelope", {
          envelope_id: envelope.id,
          source_route: sourceRoute,
        });

        if (
          this.config.securityLevel === StickinessMode.SID_ONLY &&
          envelope.sid &&
          !this.sidCache.has(envelope.sid)
        ) {
          this.sidCache.set(envelope.sid, sourceRoute);
          logger.debug("sid_only_association_recorded", {
            envelope_id: envelope.id,
            sid: envelope.sid,
            replica_id: sourceRoute,
          });
        }

        const hadInstruction = Boolean(extractAftInstruction(envelope));
        const token = await this.handleOutboundEnvelope(envelope, sourceRoute);

        if (hadInstruction) {
          logger.debug("processed_aft_setter_instruction", {
            envelope_id: envelope.id,
            source_route: sourceRoute,
            client_echo: Boolean(token),
          });
        } else {
          logger.debug("no_aft_setter_instruction", {
            envelope_id: envelope.id,
            source_route: sourceRoute,
          });
        }
      } else {
        logger.debug("downstream_envelope_without_source_route", { envelope_id: envelope.id });
      }
    } else {
      logger.debug("envelope_not_from_downstream", { envelope_id: envelope.id });
    }

    return envelope;
  }

  private storeAssociation(
    token: string,
    data: {
      replicaId: string;
      token: string;
      sid: string;
      exp: number;
      trustLevel: string;
      scope?: string | null;
      clientSid?: string | null;
    }
  ): void {
    if (this.aftAssociations.has(token)) {
      this.aftAssociations.delete(token);
    }

    const association = new AFTAssociation(data);
    this.aftAssociations.set(token, association);

    while (this.aftAssociations.size > this.cacheMax) {
      const oldest = this.aftAssociations.keys().next();
      if (oldest.done) {
        break;
      }

      const oldestToken = oldest.value;
      this.removeAssociation(oldestToken);
    }
  }

  private removeAssociation(token: string): void {
    this.aftAssociations.delete(token);
    for (const [sid, cachedToken] of this.sidCache.entries()) {
      if (cachedToken === token) {
        this.sidCache.delete(sid);
      }
    }
  }

  private routeByAft(token: string, envelope: FameEnvelope): string | null {
    const association = this.aftAssociations.get(token);
    if (!association) {
      return null;
    }

    if (association.isExpired()) {
      this.metrics.associationsExpired += 1;
      this.removeAssociation(token);
      return null;
    }

    if (
      this.verifier.securityLevel === StickinessMode.STRICT &&
      association.isLowTrust()
    ) {
      logger.warning("rejecting_low_trust_association", {
        envelope_id: envelope.id,
        replica_id: association.replicaId,
        reason: "strict mode rejects low-trust associations",
      });
      return null;
    }

    this.aftAssociations.delete(token);
    this.aftAssociations.set(token, association);
    return association.replicaId;
  }
}

function extractAftInstruction(envelope: FameEnvelope): unknown {
  if (!envelope.meta) {
    return null;
  }

  const meta = envelope.meta as Record<string, unknown>;
  const nested = meta.set;

  if (nested && typeof nested === "object" && !Array.isArray(nested)) {
    const aftValue = (nested as Record<string, unknown>).aft;
    if (aftValue !== undefined) {
      return aftValue;
    }
  }

  if (meta["set.aft"] !== undefined) {
    return meta["set.aft"];
  }

  return null;
}

function computeDeterministicIndex(key: string, modulo: number): number {
  if (modulo <= 0) {
    return 0;
  }

  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  }

  return hash % modulo;
}
