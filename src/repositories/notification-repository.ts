import type { Knex } from "knex";
import type { NotificationChannel } from "../providers/notification-provider.js";
import type { NotificationRequested } from "../services/notification-event.js";

export interface NotificationTarget {
  destination: string;
  maskedDestination: string;
}

export interface NotificationTemplate {
  id: string;
  subject_template: string | null;
  body_template: string;
}

export interface NotificationClaim {
  action: "PROCESS" | "ACK";
  notificationId: string;
  retryCount: number;
  targets: NotificationTarget[];
  template?: NotificationTemplate;
}

function maskDestination(channel: NotificationChannel, value: string): string {
  if (channel === "EMAIL") {
    const [local = "", domain = ""] = value.split("@");
    return `${local.slice(0, 1)}***@${domain}`;
  }
  if (channel === "SMS") return `${value.slice(0, 4)}******${value.slice(-3)}`;
  return `push:${value.slice(-8)}`;
}

export class NotificationRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async claim(event: NotificationRequested): Promise<NotificationClaim> {
    await this.transaction("auth_customer_inbox_events")
      .insert({
        tenant_id: event.tenant_id,
        event_id: event.event_id,
        event_type: event.event_type,
        source_service: event.producer,
        aggregate_type: event.aggregate_type,
        aggregate_id: event.aggregate_id,
        payload: {
          notification_id: event.payload.notification_id,
          recipient_id: event.payload.recipient_id,
          channel: event.payload.channel,
          template_code: event.payload.template_code,
          classification: event.payload.classification,
        },
        headers: {},
      })
      .onConflict(["source_service", "event_id"])
      .ignore();
    const inbox = await this.transaction("auth_customer_inbox_events")
      .where({ source_service: event.producer, event_id: event.event_id })
      .where({ tenant_id: event.tenant_id })
      .forUpdate()
      .first();
    if (!inbox) throw new Error("Notification inbox claim failed");
    const processingLeaseActive =
      inbox.status === "PROCESSING" &&
      inbox.next_retry_at instanceof Date &&
      inbox.next_retry_at.getTime() > Date.now();
    if (
      ["PROCESSED", "DEAD_LETTER"].includes(inbox.status) ||
      processingLeaseActive
    )
      return {
        action: "ACK",
        notificationId: event.payload.notification_id,
        retryCount: Number(inbox.retry_count),
        targets: [],
      };
    await this.transaction("auth_customer_inbox_events")
      .where({ id: inbox.id, tenant_id: event.tenant_id })
      .update({
        status: "PROCESSING",
        last_error: null,
        next_retry_at: new Date(Date.now() + 5 * 60 * 1000),
      });

    const template = await this.findTemplate(
      event.tenant_id,
      event.payload.template_code,
      event.payload.channel,
    );
    const targets = await this.findTargets(
      event.tenant_id,
      event.payload.recipient_id,
      event.payload.channel,
    );
    const contentDays =
      event.payload.classification === "NON_FINANCIAL" ? 90 : 365 * 7;
    await this.transaction("notifications")
      .insert({
        id: event.payload.notification_id,
        tenant_id: event.tenant_id,
        user_id: event.payload.recipient_id,
        template_id: template?.id ?? null,
        channel: event.payload.channel,
        recipient: targets
          .map(({ maskedDestination }) => maskedDestination)
          .join(","),
        subject: template?.subject_template ?? null,
        body: "[CONTENT_NOT_PERSISTED]",
        status: "QUEUED",
        provider_name: null,
        metadata: { template_code: event.payload.template_code },
        classification: event.payload.classification,
        content_retain_until: new Date(Date.now() + contentDays * 86_400_000),
        metadata_retain_until: new Date(Date.now() + 365 * 86_400_000),
      })
      .onConflict("id")
      .ignore();
    return {
      action: "PROCESS",
      notificationId: event.payload.notification_id,
      retryCount: Number(inbox.retry_count),
      targets,
      ...(template ? { template } : {}),
    };
  }

  public async successfulTargetHashes(
    notificationId: string,
  ): Promise<string[]> {
    const rows = await this.transaction("notification_delivery_attempts")
      .where({ notification_id: notificationId, status: "SENT" })
      .select<{ target_hash: string }[]>("target_hash");
    return rows.map(({ target_hash }) => target_hash);
  }

  public async nextAttemptNumber(
    notificationId: string,
    targetHash: string,
  ): Promise<number> {
    const result = await this.transaction("notification_delivery_attempts")
      .where({ notification_id: notificationId, target_hash: targetHash })
      .max<{ maximum: string | number | null }>("attempt_number as maximum")
      .first();
    return Number(result?.maximum ?? 0) + 1;
  }

  public async recordAttempt(input: {
    tenantId: string;
    notificationId: string;
    channel: NotificationChannel;
    providerName: string;
    providerConfigurationVersion: string;
    targetHash: string;
    hashKeyId: string;
    attemptNumber: number;
    status: "SENT" | "RETRYABLE" | "FAILED";
    providerReference?: string;
    failureCode?: string;
    nextRetryAt?: Date;
  }): Promise<void> {
    await this.transaction("notification_delivery_attempts").insert({
      tenant_id: input.tenantId,
      notification_id: input.notificationId,
      channel: input.channel,
      provider_name: input.providerName,
      provider_configuration_version: input.providerConfigurationVersion,
      target_hash: input.targetHash,
      hash_key_id: input.hashKeyId,
      attempt_number: input.attemptNumber,
      status: input.status,
      provider_reference: input.providerReference ?? null,
      failure_code: input.failureCode ?? null,
      response_metadata: {},
      completed_at: this.transaction.fn.now(),
      next_retry_at: input.nextRetryAt ?? null,
      metadata_retain_until: new Date(Date.now() + 365 * 86_400_000),
    });
  }

  public async finish(input: {
    event: NotificationRequested;
    status: "SENT" | "FAILED" | "RETRYABLE";
    providerName: string;
    providerReference?: string;
    failureCode?: string;
    nextRetryAt?: Date;
    deadLetter: boolean;
  }): Promise<void> {
    const inboxStatus = input.deadLetter
      ? "DEAD_LETTER"
      : input.status === "RETRYABLE"
        ? "FAILED"
        : "PROCESSED";
    await this.transaction("auth_customer_inbox_events")
      .where({
        tenant_id: input.event.tenant_id,
        source_service: input.event.producer,
        event_id: input.event.event_id,
      })
      .update({
        status: inboxStatus,
        retry_count:
          input.status === "RETRYABLE" || input.deadLetter
            ? this.transaction.raw("retry_count + 1")
            : this.transaction.raw("retry_count"),
        processed_at:
          inboxStatus === "PROCESSED" ? this.transaction.fn.now() : null,
        next_retry_at: input.nextRetryAt ?? null,
        last_error: input.failureCode ?? null,
      });
    await this.transaction("notifications")
      .where({
        id: input.event.payload.notification_id,
        tenant_id: input.event.tenant_id,
      })
      .update({
        status:
          input.status === "RETRYABLE"
            ? "QUEUED"
            : input.status === "SENT"
              ? "SENT"
              : "FAILED",
        provider_name: input.providerName,
        provider_reference: input.providerReference ?? null,
        failure_reason: input.failureCode ?? null,
        sent_at: input.status === "SENT" ? this.transaction.fn.now() : null,
        failed_at:
          input.status === "FAILED" || input.deadLetter
            ? this.transaction.fn.now()
            : null,
        updated_at: this.transaction.fn.now(),
      });
  }

  public async markInvalid(
    event: NotificationRequested,
    code: string,
  ): Promise<void> {
    await this.transaction("auth_customer_inbox_events")
      .where({ tenant_id: event.tenant_id, event_id: event.event_id })
      .update({ status: "DEAD_LETTER", last_error: code });
  }

  private findTemplate(
    tenantId: string,
    code: string,
    channel: NotificationChannel,
  ): Promise<NotificationTemplate | undefined> {
    return this.transaction("notification_templates")
      .where({ template_code: code, channel, is_active: true })
      .whereNull("deleted_at")
      .where((builder) =>
        builder.where({ tenant_id: tenantId }).orWhereNull("tenant_id"),
      )
      .orderByRaw("tenant_id IS NOT NULL DESC")
      .orderBy("version", "desc")
      .first() as Promise<NotificationTemplate | undefined>;
  }

  private async findTargets(
    tenantId: string,
    userId: string,
    channel: NotificationChannel,
  ): Promise<NotificationTarget[]> {
    if (channel === "PUSH") {
      const devices = await this.transaction("user_devices")
        .where({ tenant_id: tenantId, user_id: userId, status: "ACTIVE" })
        .whereNotNull("push_token")
        .whereNull("deleted_at")
        .select<{ push_token: string }[]>("push_token");
      return devices.map(({ push_token }) => ({
        destination: push_token,
        maskedDestination: maskDestination(channel, push_token),
      }));
    }
    const user = await this.transaction("users")
      .where({ tenant_id: tenantId, id: userId })
      .whereNull("deleted_at")
      .first(channel === "EMAIL" ? "email_normalized" : "phone_normalized");
    const destination =
      channel === "EMAIL" ? user?.email_normalized : user?.phone_normalized;
    return typeof destination === "string"
      ? [
          {
            destination,
            maskedDestination: maskDestination(channel, destination),
          },
        ]
      : [];
  }
}
