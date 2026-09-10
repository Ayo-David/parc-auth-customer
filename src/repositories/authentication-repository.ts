import type { Knex } from "knex";
import type { UserRecord } from "./types.js";

export interface ChallengeRecord {
  id: string;
  tenant_id: string | null;
  user_id: string | null;
  subject_id: string | null;
  subject_type: "CUSTOMER" | "ADMINISTRATOR" | null;
  scope_type: "TENANT" | "PLATFORM" | null;
  authorization_version: number | null;
  challenge_hash: string;
  challenge_type: string;
  purpose: string;
  attempts: number;
  max_attempts: number;
  expires_at: Date;
  consumed_at: Date | null;
}

export class AuthenticationRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public recordAttempt(input: {
    tenantId: string;
    userId?: string;
    identifier?: string;
    success: boolean;
    failureReason?: string;
    ipAddress?: string;
    userAgent?: string;
    deviceId?: string;
  }): Promise<number[]> {
    return this.transaction("login_attempts").insert({
      tenant_id: input.tenantId,
      user_id: input.userId ?? null,
      identifier: input.identifier ?? null,
      success: input.success,
      failure_reason: input.failureReason ?? null,
      ip_address: input.ipAddress ?? null,
      user_agent: input.userAgent ?? null,
      device_id: input.deviceId ?? null,
    });
  }

  public async recordLoginFailure(
    userId: string,
    lockAfter: number,
    lockMinutes: number,
  ): Promise<void> {
    await this.transaction("users")
      .where({ id: userId })
      .update({
        failed_login_attempts: this.transaction.raw(
          "failed_login_attempts + 1",
        ),
        locked_until: this.transaction.raw(
          "CASE WHEN failed_login_attempts + 1 >= ? THEN now() + (? * interval '1 minute') ELSE locked_until END",
          [lockAfter, lockMinutes],
        ),
      });
  }

  public async recordLoginSuccess(userId: string): Promise<void> {
    await this.transaction("users").where({ id: userId }).update({
      failed_login_attempts: 0,
      locked_until: null,
      last_login_at: this.transaction.fn.now(),
    });
  }

  public async createChallenge(input: {
    id?: string;
    tenantId: string | null;
    userId?: string;
    subjectId?: string;
    subjectType?: "CUSTOMER" | "ADMINISTRATOR";
    scopeType?: "TENANT" | "PLATFORM";
    authorizationVersion?: number;
    hash: string;
    type?: string;
    purpose: string;
    expiresAt: Date;
  }): Promise<ChallengeRecord> {
    const [record] = await this.transaction<ChallengeRecord>(
      "authentication_challenges",
    )
      .insert({
        ...(input.id ? { id: input.id } : {}),
        tenant_id: input.tenantId,
        user_id: input.userId ?? null,
        subject_id: input.subjectId ?? input.userId ?? null,
        subject_type: input.subjectType ?? (input.userId ? "CUSTOMER" : null),
        scope_type: input.scopeType ?? (input.userId ? "TENANT" : null),
        authorization_version: input.authorizationVersion ?? null,
        challenge_hash: input.hash,
        challenge_type: input.type ?? "TRANSACTION_PIN",
        purpose: input.purpose,
        expires_at: input.expiresAt,
      })
      .returning("*");
    if (!record) throw new Error("Challenge insert returned no record");
    return record;
  }

  public findChallengeForUpdate(
    id: string,
    userId: string,
    tenantId: string,
  ): Promise<ChallengeRecord | undefined> {
    return this.transaction<ChallengeRecord>("authentication_challenges")
      .where({ id, user_id: userId, tenant_id: tenantId })
      .forUpdate()
      .first();
  }

  public findChallengeByIdForUpdate(
    id: string,
    tenantId: string | null,
  ): Promise<ChallengeRecord | undefined> {
    return this.transaction<ChallengeRecord>("authentication_challenges")
      .where({ id })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .forUpdate()
      .first();
  }

  public async consumeChallenge(
    id: string,
    tenantId: string | null,
  ): Promise<void> {
    await this.transaction("authentication_challenges")
      .where({ id })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .update({ consumed_at: this.transaction.fn.now(), result: "SUCCESS" });
  }

  public async incrementChallengeFailure(
    id: string,
    tenantId: string | null,
  ): Promise<void> {
    await this.transaction("authentication_challenges")
      .where({ id })
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .update({
        attempts: this.transaction.raw("attempts + 1"),
        result: "FAILED",
      });
  }
}

export function isUserLocked(
  user: UserRecord & { locked_until?: Date | null },
): boolean {
  return Boolean(user.locked_until && user.locked_until.getTime() > Date.now());
}
