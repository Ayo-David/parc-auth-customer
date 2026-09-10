import { createHmac, randomUUID } from "node:crypto";
import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import type { OtpSecretStore } from "../security/otp-secret-store.js";
import type { NotificationProviderRegistry } from "../providers/notification-provider.js";
import { NotificationRepository } from "../repositories/notification-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import {
  notificationRequestedSchema,
  type NotificationRequested,
} from "./notification-event.js";

export interface NotificationHandlingResult {
  action: "ACK" | "RETRY" | "DEAD_LETTER";
  retryDelayMs?: number;
}

function render(template: string, data: Record<string, unknown>): string {
  return template.replace(
    /{{\s*([a-zA-Z0-9_]+)\s*}}/g,
    (_match, key: string) => {
      const value = data[key];
      return typeof value === "string" || typeof value === "number"
        ? String(value)
        : "";
    },
  );
}

export class NotificationWorkerService {
  public constructor(
    private readonly database: Knex,
    private readonly providers: NotificationProviderRegistry,
    private readonly otpSecrets: OtpSecretStore,
    private readonly targetHashSecret: string,
    private readonly targetHashKeyId: string,
    private readonly maxAttempts: number,
    private readonly baseRetryDelayMs: number,
  ) {}

  public async handle(rawEvent: unknown): Promise<NotificationHandlingResult> {
    const event = notificationRequestedSchema.parse(rawEvent);
    const claim = await withTenantTransaction(
      this.database,
      event.tenant_id,
      (transaction) => new NotificationRepository(transaction).claim(event),
    );
    if (claim.action === "ACK") return { action: "ACK" };
    const provider = this.providers.resolve(event.payload.channel);
    const templateData = { ...event.payload.template_data };
    if ("challenge_id" in templateData) {
      const secret = await this.otpSecrets.take(
        String(templateData.challenge_id),
      );
      if (!secret)
        return this.finishPermanentFailure(
          event,
          provider.name,
          "EPHEMERAL_CONTENT_EXPIRED",
        );
      try {
        const parsed = JSON.parse(secret) as { code?: unknown };
        templateData.otp =
          typeof parsed.code === "string" ? parsed.code : secret;
      } catch {
        templateData.otp = secret;
      }
    }
    const subjectTemplate =
      claim.template?.subject_template ?? "Parc security code";
    const bodyTemplate =
      claim.template?.body_template ??
      ("challenge_id" in templateData
        ? "Your Parc verification code is {{otp}}. It expires shortly."
        : undefined);
    if (!bodyTemplate)
      return this.finishPermanentFailure(
        event,
        provider.name,
        "NOTIFICATION_TEMPLATE_NOT_FOUND",
      );
    if (claim.targets.length === 0)
      return this.finishPermanentFailure(
        event,
        provider.name,
        "DELIVERY_TARGET_UNAVAILABLE",
      );

    const successful = await withTenantTransaction(
      this.database,
      event.tenant_id,
      (transaction) =>
        new NotificationRepository(transaction).successfulTargetHashes(
          claim.notificationId,
        ),
    );
    const sentReferences: string[] = [];
    let retryable = false;
    let permanentFailure = false;
    let lastFailureCode: string | undefined;
    const nextRetryAt = new Date(
      Date.now() +
        this.baseRetryDelayMs * 2 ** claim.retryCount +
        Math.floor(Math.random() * this.baseRetryDelayMs),
    );

    for (const target of claim.targets) {
      const targetHash = this.hashTarget(event, target.destination);
      if (successful.includes(targetHash)) continue;
      const result = await provider.send({
        notificationId: event.payload.notification_id,
        destination: target.destination,
        subject: render(subjectTemplate, templateData),
        body: render(bodyTemplate, templateData),
        data: {
          notification_id: event.payload.notification_id,
          template_code: event.payload.template_code,
        },
      });
      const attemptNumber = await withTenantTransaction(
        this.database,
        event.tenant_id,
        (transaction) =>
          new NotificationRepository(transaction).nextAttemptNumber(
            claim.notificationId,
            targetHash,
          ),
      );
      await withTenantTransaction(
        this.database,
        event.tenant_id,
        (transaction) =>
          new NotificationRepository(transaction).recordAttempt({
            tenantId: event.tenant_id,
            notificationId: claim.notificationId,
            channel: event.payload.channel,
            providerName: provider.name,
            providerConfigurationVersion: provider.configurationVersion,
            targetHash,
            hashKeyId: this.targetHashKeyId,
            attemptNumber,
            status: result.status,
            ...(result.providerReference
              ? { providerReference: result.providerReference }
              : {}),
            ...(result.failureCode ? { failureCode: result.failureCode } : {}),
            ...(result.status === "RETRYABLE" ? { nextRetryAt } : {}),
          }),
      );
      if (result.providerReference)
        sentReferences.push(result.providerReference);
      if (result.status === "RETRYABLE") retryable = true;
      if (result.status === "FAILED") permanentFailure = true;
      lastFailureCode = result.failureCode ?? lastFailureCode;
    }

    const exhausted = retryable && claim.retryCount + 1 >= this.maxAttempts;
    const status =
      retryable && !exhausted
        ? "RETRYABLE"
        : permanentFailure || exhausted
          ? "FAILED"
          : "SENT";
    await withTenantTransaction(
      this.database,
      event.tenant_id,
      async (transaction) => {
        const repository = new NotificationRepository(transaction);
        await repository.finish({
          event,
          status,
          providerName: provider.name,
          ...(sentReferences.length === 1
            ? { providerReference: sentReferences[0] }
            : {}),
          ...(lastFailureCode ? { failureCode: lastFailureCode } : {}),
          ...(status === "RETRYABLE" ? { nextRetryAt } : {}),
          deadLetter: exhausted,
        });
        if (status !== "RETRYABLE")
          await this.publishDelivery(
            transaction,
            event,
            status === "SENT" ? "SENT" : "FAILED",
            sentReferences.length === 1 ? sentReferences[0] : undefined,
            lastFailureCode,
          );
      },
    );
    if (exhausted) return { action: "DEAD_LETTER" };
    if (status === "RETRYABLE")
      return {
        action: "RETRY",
        retryDelayMs: nextRetryAt.getTime() - Date.now(),
      };
    return { action: "ACK" };
  }

  private hashTarget(
    event: NotificationRequested,
    destination: string,
  ): string {
    return createHmac("sha256", this.targetHashSecret)
      .update(`${event.tenant_id}:${event.payload.channel}:${destination}`)
      .digest("hex");
  }

  private async finishPermanentFailure(
    event: NotificationRequested,
    providerName: string,
    failureCode: string,
  ): Promise<NotificationHandlingResult> {
    await withTenantTransaction(
      this.database,
      event.tenant_id,
      async (transaction) => {
        await new NotificationRepository(transaction).finish({
          event,
          status: "FAILED",
          providerName,
          failureCode,
          deadLetter: false,
        });
        await this.publishDelivery(
          transaction,
          event,
          "FAILED",
          undefined,
          failureCode,
        );
      },
    );
    return { action: "ACK" };
  }

  private async publishDelivery(
    transaction: Knex.Transaction,
    event: NotificationRequested,
    status: "SENT" | "FAILED",
    providerReference?: string,
    failureCode?: string,
  ): Promise<void> {
    const eventId = randomUUID();
    await new EventRepository(transaction).publish({
      tenantId: event.tenant_id,
      eventId,
      eventType: "notification.delivery-recorded.v1",
      aggregateType: "notification",
      aggregateId: event.payload.notification_id,
      payload: {
        event_id: eventId,
        event_type: "notification.delivery-recorded.v1",
        event_version: 1,
        occurred_at: new Date().toISOString(),
        producer: "parc-auth-customer",
        tenant_id: event.tenant_id,
        aggregate_type: "notification",
        aggregate_id: event.payload.notification_id,
        aggregate_version: 1,
        correlation_id: event.correlation_id,
        causation_id: event.event_id,
        idempotency_key: event.idempotency_key,
        data_classification: "CONFIDENTIAL",
        payload: {
          notification_id: event.payload.notification_id,
          channel: event.payload.channel,
          status,
          provider_reference: providerReference ?? null,
          failure_code: failureCode ?? null,
          recorded_at: new Date().toISOString(),
        },
      },
    });
  }
}
