import { randomUUID } from "node:crypto";
import amqp, { type ChannelModel, type ConfirmChannel } from "amqplib";
import type { Knex } from "knex";
import type { Logger } from "pino";
import { withTenantTransaction } from "../database/transaction.js";

const exchange = "parc.events";
const leaseSeconds = 60;
const maxRetries = 10;

interface OutboxRow {
  id: string;
  tenant_id: string;
  event_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  retry_count: number;
  created_at: Date;
}

/**
 * Relays committed outbox rows to the `parc.events` topic exchange, routed by
 * event type. Rows already hold the full event envelope.
 */
export class OutboxPublisher {
  private connection: ChannelModel | undefined;
  private channel: ConfirmChannel | undefined;
  private timer: NodeJS.Timeout | undefined;
  private publishing = false;
  private readonly workerId = `parc-auth-customer:${randomUUID()}`;

  public constructor(
    private readonly database: Knex,
    private readonly url: string,
    private readonly tenantIds: readonly string[],
    private readonly pollMs: number,
    private readonly logger: Logger,
    /** Test seam; defaults to a confirm channel on `url`. */
    private readonly openChannel?: () => Promise<ConfirmChannel>,
  ) {}

  public start(): void {
    this.timer = setInterval(() => {
      void this.tick();
    }, this.pollMs);
    this.timer.unref();
  }

  public async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.channel?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
  }

  /** Publishes one batch for every configured tenant; returns rows published. */
  public async tick(): Promise<number> {
    if (this.publishing) return 0;
    this.publishing = true;
    try {
      let published = 0;
      for (const tenantId of this.tenantIds)
        published += await this.publishTenantBatch(tenantId);
      return published;
    } catch (error) {
      this.logger.error({ err: error }, "Outbox publish failed");
      return 0;
    } finally {
      this.publishing = false;
    }
  }

  private async publishTenantBatch(tenantId: string): Promise<number> {
    const channel = await this.connect();
    const rows = await this.claim(tenantId);
    if (rows.length === 0) return 0;
    let published = 0;
    for (const row of rows) {
      try {
        channel.publish(
          exchange,
          row.event_type,
          Buffer.from(JSON.stringify(row.payload)),
          {
            persistent: true,
            contentType: "application/json",
            messageId: row.event_id,
            type: row.event_type,
            timestamp: Math.floor(row.created_at.getTime() / 1000),
          },
        );
        await channel.waitForConfirms();
        await this.finish(row, undefined);
        published += 1;
      } catch (error) {
        this.channel = undefined;
        await this.finish(row, error);
        throw error;
      }
    }
    return published;
  }

  private claim(tenantId: string): Promise<OutboxRow[]> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      await tx("auth_customer_outbox_events")
        .where({ tenant_id: tenantId, status: "PROCESSING" })
        .where(
          "locked_at",
          "<=",
          tx.raw(`now() - interval '${String(leaseSeconds)} seconds'`),
        )
        .update({ status: "PENDING", locked_at: null, locked_by: null });
      const rows = await tx<OutboxRow>("auth_customer_outbox_events")
        .where({ tenant_id: tenantId })
        .whereIn("status", ["PENDING", "FAILED"])
        .where("available_at", "<=", tx.fn.now())
        .orderBy("created_at")
        .forUpdate()
        .skipLocked()
        .limit(50)
        .select(
          "id",
          "tenant_id",
          "event_id",
          "event_type",
          "payload",
          "retry_count",
          "created_at",
        );
      if (rows.length > 0)
        await tx("auth_customer_outbox_events")
          .whereIn(
            "id",
            rows.map((row) => row.id),
          )
          .update({
            status: "PROCESSING",
            locked_at: tx.fn.now(),
            locked_by: this.workerId,
          });
      return rows;
    });
  }

  private async finish(row: OutboxRow, error: unknown): Promise<void> {
    await withTenantTransaction(this.database, row.tenant_id, (tx) =>
      tx("auth_customer_outbox_events")
        .where({ id: row.id, status: "PROCESSING", locked_by: this.workerId })
        .update(
          error === undefined
            ? {
                status: "PUBLISHED",
                published_at: tx.fn.now(),
                locked_at: null,
                locked_by: null,
                last_error: null,
              }
            : {
                status:
                  row.retry_count + 1 >= maxRetries ? "DEAD_LETTER" : "FAILED",
                retry_count: row.retry_count + 1,
                available_at: tx.raw(
                  "now() + least(interval '5 minutes', interval '1 second' * power(2, ?))",
                  [row.retry_count],
                ),
                locked_at: null,
                locked_by: null,
                last_error:
                  error instanceof Error
                    ? error.message.slice(0, 1000)
                    : "Publish failed",
              },
        ),
    );
  }

  private async connect(): Promise<ConfirmChannel> {
    if (this.channel) return this.channel;
    if (this.openChannel) {
      this.channel = await this.openChannel();
      return this.channel;
    }
    const connection = await amqp.connect(this.url);
    const reset = () => {
      if (this.connection === connection) {
        this.connection = undefined;
        this.channel = undefined;
      }
    };
    connection.on("error", reset);
    connection.on("close", reset);
    try {
      const channel = await connection.createConfirmChannel();
      channel.on("error", reset);
      channel.on("close", reset);
      await channel.assertExchange(exchange, "topic", { durable: true });
      this.connection = connection;
      this.channel = channel;
      return channel;
    } catch (error) {
      await connection.close().catch(() => undefined);
      throw error;
    }
  }
}
