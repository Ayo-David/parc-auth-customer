import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";

export class CustomerExperienceService {
  public constructor(private readonly database: Knex) {}

  public security(
    tenantId: string,
    userId: string,
  ): Promise<Record<string, unknown>> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const [credentials, devices, sessions] = await Promise.all([
        tx("user_credentials")
          .where({ tenant_id: tenantId, user_id: userId, is_active: true })
          .whereNull("deleted_at")
          .select("credential_type", "last_used_at", "created_at"),
        tx("user_devices")
          .where({ tenant_id: tenantId, user_id: userId })
          .whereNull("deleted_at")
          .select(
            "id",
            "device_name",
            "platform",
            "status",
            "is_trusted",
            "last_seen_at",
          ),
        tx("user_sessions")
          .where({ tenant_id: tenantId, subject_id: userId })
          .whereNull("revoked_at")
          .whereNull("deleted_at")
          .where("expires_at", ">", tx.fn.now())
          .select(
            "id",
            "device_id",
            "authentication_methods",
            "mfa_verified_at",
            "last_activity_at",
            "expires_at",
          ),
      ]);
      return { credentials, devices, active_sessions: sessions };
    });
  }

  public notifications(
    tenantId: string,
    userId: string,
    pageSize: number,
  ): Promise<{ items: unknown[] }> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const rows = await tx("notifications")
        .where({ tenant_id: tenantId, user_id: userId })
        .orderBy("created_at", "desc")
        .limit(pageSize)
        .select(
          "id",
          "channel",
          "subject",
          "body",
          "status",
          "classification",
          "read_at",
          "created_at",
          "content_retain_until",
        );
      const now = Date.now();
      return {
        items: rows.map((row: Record<string, unknown>) => {
          const retained =
            row.content_retain_until === null ||
            new Date(String(row.content_retain_until)).getTime() > now;
          const { content_retain_until: _retention, ...metadata } = row;
          void _retention;
          return retained
            ? metadata
            : { ...metadata, subject: null, body: null, content_expired: true };
        }),
      };
    });
  }

  public referralSummary(
    tenantId: string,
    userId: string,
  ): Promise<Record<string, unknown>> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const referral = await tx("referrals as r")
        .join("referral_programs as p", "p.id", "r.program_id")
        .where({
          "r.tenant_id": tenantId,
          "r.referrer_user_id": userId,
          "p.is_active": true,
        })
        .whereNull("p.deleted_at")
        .orderBy("r.created_at", "desc")
        .first("r.referral_code", "p.name as program_name", "p.reward_rules");
      const reward = await tx("referral_rewards")
        .where({ tenant_id: tenantId, beneficiary_user_id: userId })
        .sum<{ total: string | null }>("amount_minor as total")
        .first();
      return {
        referral_code: referral?.referral_code ?? null,
        program_name: referral?.program_name ?? null,
        policy: referral?.reward_rules ?? null,
        earned_reward_minor: reward?.total ?? "0",
        currency: "NGN",
      };
    });
  }
}
