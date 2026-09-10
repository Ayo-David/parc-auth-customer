import { createHmac, randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import type {
  NotificationMessage,
  NotificationProvider,
  NotificationProviderResult,
} from "../../src/providers/notification-provider.js";
import { StaticNotificationProviderRegistry } from "../../src/providers/notification-provider.js";
import { MemoryOtpSecretStore } from "../../src/security/otp-secret-store.js";
import { NotificationWorkerService } from "../../src/services/notification-worker-service.js";
import type { NotificationRequested } from "../../src/services/notification-event.js";
import { NotificationRetentionService } from "../../src/services/notification-retention-service.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

class SequenceProvider implements NotificationProvider {
  public readonly name = "TERMII" as const;
  public readonly configurationVersion = "termii-v1";
  public readonly messages: NotificationMessage[] = [];
  public constructor(private readonly results: NotificationProviderResult[]) {}
  public send(
    message: NotificationMessage,
  ): Promise<NotificationProviderResult> {
    this.messages.push(message);
    return Promise.resolve(
      this.results.shift() ?? { status: "SENT", providerReference: "default" },
    );
  }
}

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});

afterAll(async () => database.destroy());

async function fixture(
  tenantId: string,
): Promise<{ userId: string; event: NotificationRequested }> {
  const userId = randomUUID();
  await withTenantTransaction(database, tenantId, async (transaction) => {
    await transaction("users").insert({
      id: userId,
      tenant_id: tenantId,
      user_type: "CUSTOMER",
      status: "ACTIVE",
      phone: "+2348012345678",
      phone_normalized: "+2348012345678",
    });
    await transaction("notification_templates").insert({
      tenant_id: tenantId,
      template_code: "OTP_LOGIN",
      channel: "SMS",
      body_template: "Your code is {{otp}}",
      version: 1,
    });
  });
  const notificationId = randomUUID();
  const challengeId = randomUUID();
  return {
    userId,
    event: {
      event_id: randomUUID(),
      event_type: "notification.requested.v1",
      event_version: 1,
      occurred_at: new Date().toISOString(),
      producer: "parc-auth-customer",
      tenant_id: tenantId,
      aggregate_type: "notification",
      aggregate_id: notificationId,
      aggregate_version: 1,
      correlation_id: randomUUID(),
      causation_id: null,
      idempotency_key: randomUUID(),
      data_classification: "RESTRICTED",
      payload: {
        notification_id: notificationId,
        recipient_id: userId,
        channel: "SMS",
        template_code: "OTP_LOGIN",
        classification: "SECURITY",
        template_data: { challenge_id: challengeId },
      },
    },
  };
}

function worker(
  provider: NotificationProvider,
  secrets: MemoryOtpSecretStore,
  max = 3,
) {
  return new NotificationWorkerService(
    database,
    new StaticNotificationProviderRegistry({
      EMAIL: provider,
      SMS: provider,
      PUSH: provider,
    }),
    secrets,
    "t".repeat(32),
    "target-v1",
    max,
    10,
  );
}

async function cleanup(tenantId: string): Promise<void> {
  await database.raw("TRUNCATE notification_delivery_attempts");
  await database("notifications").where({ tenant_id: tenantId }).delete();
  await database("notification_templates")
    .where({ tenant_id: tenantId })
    .delete();
  await database("auth_customer_inbox_events")
    .where({ tenant_id: tenantId })
    .delete();
  await database("auth_customer_outbox_events")
    .where({ tenant_id: tenantId })
    .delete();
  await database("users").where({ tenant_id: tenantId }).delete();
}

integrationTest(
  "delivers once, redacts persistence, and acknowledges duplicate events",
  async () => {
    const tenantId = randomUUID();
    const { event } = await fixture(tenantId);
    const challengeId = String(event.payload.template_data.challenge_id);
    const secrets = new MemoryOtpSecretStore();
    await secrets.put(challengeId, "123456", 300);
    const provider = new SequenceProvider([
      { status: "SENT", providerReference: "termii-message-1" },
    ]);
    const service = worker(provider, secrets);

    expect(await service.handle(event)).toEqual({ action: "ACK" });
    expect(await service.handle(event)).toEqual({ action: "ACK" });
    expect(provider.messages).toHaveLength(1);
    expect(provider.messages[0]?.destination).toBe("+2348012345678");
    expect(provider.messages[0]?.body).toContain("123456");

    const notification = await database("notifications")
      .where({ tenant_id: tenantId })
      .first();
    expect(notification.recipient).toBe("+234******678");
    expect(notification.body).toBe("[CONTENT_NOT_PERSISTED]");
    expect(JSON.stringify(notification)).not.toContain("123456");
    expect(notification.content_retain_until).toBeTruthy();
    expect(notification.metadata_retain_until).toBeTruthy();
    const attempt = await database("notification_delivery_attempts")
      .where({ tenant_id: tenantId })
      .first();
    expect(attempt.target_hash).toBe(
      createHmac("sha256", "t".repeat(32))
        .update(`${tenantId}:SMS:+2348012345678`)
        .digest("hex"),
    );
    expect(JSON.stringify(attempt)).not.toContain("+2348012345678");
    expect(
      await database("auth_customer_outbox_events")
        .where({
          tenant_id: tenantId,
          event_type: "notification.delivery-recorded.v1",
        })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);

    await withTenantTransaction(database, tenantId, async (transaction) => {
      await transaction("notifications")
        .where({ id: notification.id })
        .update({
          body: "temporary content",
          recipient: "+234******678",
          metadata: { temporary: true },
          content_retain_until: new Date(Date.now() - 1_000),
          metadata_retain_until: new Date(Date.now() - 1_000),
        });
      const [expired] = await transaction("notification_delivery_attempts")
        .insert({
          tenant_id: tenantId,
          notification_id: notification.id,
          channel: "SMS",
          provider_name: "TERMII",
          provider_configuration_version: "termii-v1",
          target_hash: "expired-target-hash",
          hash_key_id: "target-v1",
          attempt_number: 1,
          status: "PROCESSING",
          metadata_retain_until: new Date(Date.now() - 1_000),
        })
        .returning("id");
      await transaction("notification_delivery_attempts")
        .where({ id: expired.id })
        .update({ status: "SENT", completed_at: transaction.fn.now() });
    });
    expect(
      await new NotificationRetentionService(database).run(tenantId),
    ).toEqual({
      contentRedacted: 1,
      metadataRedacted: 1,
      attemptsDeleted: 1,
    });
    expect(
      await database("notifications")
        .where({ id: notification.id })
        .first("body"),
    ).toEqual({ body: "[CONTENT_REDACTED]" });
    await cleanup(tenantId);
  },
  15_000,
);

integrationTest(
  "records retry attempts and dead-letters after the configured bound",
  async () => {
    const tenantId = randomUUID();
    const { event } = await fixture(tenantId);
    const challengeId = String(event.payload.template_data.challenge_id);
    const secrets = new MemoryOtpSecretStore();
    await secrets.put(challengeId, "654321", 300);
    const provider = new SequenceProvider([
      { status: "RETRYABLE", failureCode: "HTTP_503" },
      { status: "RETRYABLE", failureCode: "HTTP_503" },
    ]);
    const service = worker(provider, secrets, 2);
    expect((await service.handle(event)).action).toBe("RETRY");
    expect(await service.handle(event)).toEqual({ action: "DEAD_LETTER" });
    expect(provider.messages).toHaveLength(2);
    const inbox = await database("auth_customer_inbox_events")
      .where({ tenant_id: tenantId })
      .first();
    expect(inbox.status).toBe("DEAD_LETTER");
    expect(inbox.retry_count).toBe(2);
    expect(
      await database("notification_delivery_attempts")
        .where({ tenant_id: tenantId })
        .count("* as count"),
    ).toEqual([{ count: "2" }]);
    await cleanup(tenantId);
  },
  15_000,
);
