import type { Knex } from "knex";
import type { SessionRecord } from "./types.js";

export class SessionRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async create(input: {
    tenantId: string | null;
    userId: string | null;
    subjectId?: string;
    sessionTokenHash: string;
    refreshTokenHash: string;
    tokenFamilyId: string;
    rotationSequence: number;
    audience: string;
    subjectType: "CUSTOMER" | "ADMINISTRATOR";
    scopeType?: "TENANT" | "PLATFORM";
    authorizationVersion?: number;
    authenticationMethods: string[];
    expiresAt: Date;
    idleExpiresAt: Date;
    deviceId?: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<SessionRecord> {
    const [record] = await this.transaction("user_sessions")
      .insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        subject_id: input.subjectId ?? input.userId,
        session_token_hash: input.sessionTokenHash,
        refresh_token_hash: input.refreshTokenHash,
        token_family_id: input.tokenFamilyId,
        rotation_sequence: input.rotationSequence,
        audience: input.audience,
        subject_type: input.subjectType,
        scope_type: input.scopeType ?? "TENANT",
        authorization_version: input.authorizationVersion ?? null,
        authentication_methods: input.authenticationMethods,
        expires_at: input.expiresAt,
        idle_expires_at: input.idleExpiresAt,
        device_id: input.deviceId ?? null,
        ip_address: input.ipAddress ?? null,
        user_agent: input.userAgent ?? null,
      })
      .returning("*");
    if (!record) throw new Error("Session insert returned no record");
    return record as SessionRecord;
  }

  public findActiveByRefreshTokenHash(
    tenantId: string,
    hash: string,
  ): Promise<SessionRecord | undefined> {
    return this.transaction<SessionRecord>("user_sessions")
      .where({ tenant_id: tenantId, refresh_token_hash: hash })
      .whereNull("revoked_at")
      .whereNull("deleted_at")
      .where("expires_at", ">", this.transaction.fn.now())
      .first();
  }

  public findByRefreshTokenHashForUpdate(
    tenantId: string | null,
    hash: string,
  ): Promise<SessionRecord | undefined> {
    return this.transaction<SessionRecord>("user_sessions")
      .where({ refresh_token_hash: hash })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .whereNull("deleted_at")
      .forUpdate()
      .first();
  }

  public findById(
    tenantId: string | null,
    id: string,
  ): Promise<SessionRecord | undefined> {
    return this.transaction<SessionRecord>("user_sessions")
      .where({ id })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .whereNull("deleted_at")
      .first();
  }

  public async replace(oldId: string, newId: string): Promise<void> {
    await this.transaction("user_sessions").where({ id: oldId }).update({
      revoked_at: this.transaction.fn.now(),
      replaced_by_session_id: newId,
    });
  }

  public async markFamilyCompromised(
    tokenFamilyId: string,
    at = new Date(),
  ): Promise<void> {
    await this.transaction("user_sessions")
      .where({ token_family_id: tokenFamilyId })
      .update({
        revoked_at: this.transaction.raw("COALESCE(revoked_at, ?)", [at]),
        reuse_detected_at: at,
        compromised_at: at,
      });
  }

  public async revokeSession(
    tenantId: string | null,
    id: string,
  ): Promise<number> {
    return this.transaction("user_sessions")
      .where({ id })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .whereNull("revoked_at")
      .update({ revoked_at: this.transaction.fn.now() });
  }

  public async revokeFamily(
    tokenFamilyId: string,
    at = new Date(),
  ): Promise<number> {
    return this.transaction("user_sessions")
      .where({ token_family_id: tokenFamilyId })
      .whereNull("revoked_at")
      .update({ revoked_at: at });
  }
}
