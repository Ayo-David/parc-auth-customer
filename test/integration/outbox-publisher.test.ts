import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import type { ConfirmChannel } from "amqplib";
import knex, { type Knex } from "knex";
import pino from "pino";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { OutboxPublisher } from "../../src/messaging/outbox-publisher.js";
import { EventRepository } from "../../src/repositories/event-repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});
afterAll(async () => database.destroy());

async function enqueue(tenantId: string): Promise<string> {
  const eventId = randomUUID();
  await withTenantTransaction(database, tenantId, (transaction) =>
    new EventRepository(transaction).publish({
      tenantId,
      eventId,
      eventType: "notification.requested.v1",
      aggregateType: "notification",
      aggregateId: eventId,
      payload: { event_id: eventId, tenant_id: tenantId },
    }),
  );
  return eventId;
}

function fakeChannel(confirm: () => Promise<void>) {
  const publish = jest.fn(() => true);
  const channel = {
    publish,
    waitForConfirms: jest.fn(confirm),
    close: jest.fn(async () => undefined),
  };
  return { publish, channel: channel as unknown as ConfirmChannel };
}

function publisher(tenantIds: string[], channel: ConfirmChannel) {
  return new OutboxPublisher(
    database,
    "amqp://unused",
    tenantIds,
    1_000,
    pino({ level: "silent" }),
    async () => channel,
  );
}

integrationTest(
  "relays outbox events to RabbitMQ by event type and marks them published",
  async () => {
    const tenantId = randomUUID();
    const otherTenantId = randomUUID();
    const eventId = await enqueue(tenantId);
    const otherEventId = await enqueue(otherTenantId);
    const { publish, channel } = fakeChannel(async () => undefined);

    expect(await publisher([tenantId], channel).tick()).toBe(1);

    expect(publish).toHaveBeenCalledWith(
      "parc.events",
      "notification.requested.v1",
      Buffer.from(JSON.stringify({ event_id: eventId, tenant_id: tenantId })),
      expect.objectContaining({ messageId: eventId, persistent: true }),
    );
    const rows = await database("auth_customer_outbox_events")
      .whereIn("event_id", [eventId, otherEventId])
      .select("event_id", "status", "published_at", "locked_by");
    expect(rows.find((row) => row.event_id === eventId)).toMatchObject({
      status: "PUBLISHED",
      locked_by: null,
    });
    // Only configured tenants are relayed.
    expect(rows.find((row) => row.event_id === otherEventId)).toMatchObject({
      status: "PENDING",
    });
    await database("auth_customer_outbox_events")
      .whereIn("tenant_id", [tenantId, otherTenantId])
      .delete();
  },
  15_000,
);

integrationTest(
  "backs off an event the broker did not confirm",
  async () => {
    const tenantId = randomUUID();
    const eventId = await enqueue(tenantId);
    const { channel } = fakeChannel(async () =>
      Promise.reject(new Error("nack")),
    );

    expect(await publisher([tenantId], channel).tick()).toBe(0);

    const row = await database("auth_customer_outbox_events")
      .where({ event_id: eventId })
      .first();
    expect(row).toMatchObject({
      status: "FAILED",
      retry_count: 1,
      last_error: "nack",
      locked_by: null,
    });
    expect(row.available_at.getTime()).toBeGreaterThan(Date.now());
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
  },
  15_000,
);
