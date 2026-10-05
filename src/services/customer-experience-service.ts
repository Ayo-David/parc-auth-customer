import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import { CustomerRepository } from "../repositories/customer-repository.js";

export class CustomerExperienceService {
  public constructor(private readonly database: Knex) {}

  /** Customer access tokens carry the profile ID; user-owned rows key on users.id. */
  public userIdForCustomer(
    tenantId: string,
    customerId: string,
  ): Promise<string> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const profile = await new CustomerRepository(tx).findById(customerId);
      if (!profile)
        throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
      return profile.user_id;
    });
  }

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
          const retainUntil = row.content_retain_until;
          const retained =
            retainUntil === null ||
            (retainUntil instanceof Date
              ? retainUntil.getTime()
              : typeof retainUntil === "string"
                ? new Date(retainUntil).getTime()
                : 0) > now;
          const metadata = { ...row };
          delete metadata.content_retain_until;
          return retained
            ? metadata
            : { ...metadata, subject: null, body: null, content_expired: true };
        }),
      };
    });
  }

  public notificationPreferences(
    tenantId: string,
    userId: string,
  ): Promise<{ items: unknown[] }> {
    return withTenantTransaction(this.database, tenantId, async (tx) => ({
      items: await tx("notification_preferences")
        .where({ tenant_id: tenantId, user_id: userId })
        .orderBy("notification_category")
        .select(
          "notification_category",
          "push_enabled",
          "sms_enabled",
          "email_enabled",
          "in_app_enabled",
          "updated_at",
        ),
    }));
  }

  public updateNotificationPreference(input: {
    tenantId: string;
    userId: string;
    category: string;
    pushEnabled: boolean;
    smsEnabled: boolean;
    emailEnabled: boolean;
    inAppEnabled: boolean;
  }): Promise<Record<string, unknown>> {
    return withTenantTransaction(this.database, input.tenantId, async (tx) => {
      const [row] = await tx("notification_preferences")
        .insert({
          tenant_id: input.tenantId,
          user_id: input.userId,
          notification_category: input.category,
          push_enabled: input.pushEnabled,
          sms_enabled: input.smsEnabled,
          email_enabled: input.emailEnabled,
          in_app_enabled: input.inAppEnabled,
        })
        .onConflict(["user_id", "notification_category"])
        .merge({
          push_enabled: input.pushEnabled,
          sms_enabled: input.smsEnabled,
          email_enabled: input.emailEnabled,
          in_app_enabled: input.inAppEnabled,
          updated_at: tx.fn.now(),
        })
        .returning([
          "notification_category",
          "push_enabled",
          "sms_enabled",
          "email_enabled",
          "in_app_enabled",
          "updated_at",
        ]);
      if (!row) throw new Error("Notification preference was not persisted");
      return row as Record<string, unknown>;
    });
  }

  public registerPushDevice(input: {
    tenantId: string;
    userId: string;
    deviceIdentifier: string;
    pushToken: string;
    platform: "ANDROID" | "IOS";
    deviceName?: string;
    osVersion?: string;
    appVersion?: string;
  }): Promise<Record<string, unknown>> {
    return withTenantTransaction(this.database, input.tenantId, async (tx) => {
      await tx.raw("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", [
        `${input.tenantId}:${input.userId}:${input.deviceIdentifier}`,
      ]);
      const existingRows = await tx<{
        id: string;
        tenant_id: string;
        user_id: string;
        device_identifier: string;
        deleted_at: Date | null;
      }>("user_devices")
        .where({
          tenant_id: input.tenantId,
          user_id: input.userId,
          device_identifier: input.deviceIdentifier,
        })
        .whereNull("deleted_at")
        .limit(1)
        .select("id");
      const existing = existingRows[0];
      const values = {
        push_token: input.pushToken,
        platform: input.platform,
        device_name: input.deviceName ?? null,
        os_version: input.osVersion ?? null,
        app_version: input.appVersion ?? null,
        status: "ACTIVE",
        last_seen_at: tx.fn.now(),
        updated_at: tx.fn.now(),
      };
      const [row] = existing
        ? await tx("user_devices")
            .where({ id: existing.id })
            .update(values)
            .returning([
              "id",
              "device_name",
              "platform",
              "status",
              "last_seen_at",
            ])
        : await tx("user_devices")
            .insert({
              tenant_id: input.tenantId,
              user_id: input.userId,
              device_identifier: input.deviceIdentifier,
              ...values,
            })
            .returning([
              "id",
              "device_name",
              "platform",
              "status",
              "last_seen_at",
            ]);
      if (!row) throw new Error("Push device was not persisted");
      return row as Record<string, unknown>;
    });
  }

  public revokeDevice(
    tenantId: string,
    userId: string,
    deviceId: string,
  ): Promise<void> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const changed = await tx("user_devices")
        .where({ id: deviceId, tenant_id: tenantId, user_id: userId })
        .whereNull("deleted_at")
        .update({
          status: "REVOKED",
          push_token: null,
          is_trusted: false,
          deleted_at: tx.fn.now(),
          updated_at: tx.fn.now(),
        });
      if (changed === 0) {
        const existing = await tx("user_devices")
          .where({ id: deviceId, tenant_id: tenantId, user_id: userId })
          .first("id");
        if (!existing) throw new ApiError(404, "NOT_FOUND", "Device not found");
      }
      await tx("user_sessions")
        .where({ tenant_id: tenantId, subject_id: userId, device_id: deviceId })
        .whereNull("revoked_at")
        .update({ revoked_at: tx.fn.now(), refresh_token_hash: null });
    });
  }

  public revokeSession(
    tenantId: string,
    userId: string,
    sessionId: string,
  ): Promise<void> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const changed = await tx("user_sessions")
        .where({ id: sessionId, tenant_id: tenantId, subject_id: userId })
        .whereNull("revoked_at")
        .update({ revoked_at: tx.fn.now(), refresh_token_hash: null });
      if (changed === 0) {
        const existing = await tx("user_sessions")
          .where({ id: sessionId, tenant_id: tenantId, subject_id: userId })
          .first("id");
        if (!existing)
          throw new ApiError(404, "NOT_FOUND", "Session not found");
      }
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
