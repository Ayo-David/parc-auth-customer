import type { Knex } from "knex";

export class EventRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async receive(input: {
    tenantId: string;
    eventId: string;
    eventType: string;
    sourceService: string;
    aggregateType?: string;
    aggregateId?: string;
    payload: object;
    headers?: object;
  }): Promise<boolean> {
    const rows = await this.transaction("auth_customer_inbox_events")
      .insert({
        tenant_id: input.tenantId,
        event_id: input.eventId,
        event_type: input.eventType,
        source_service: input.sourceService,
        aggregate_type: input.aggregateType ?? null,
        aggregate_id: input.aggregateId ?? null,
        payload: input.payload,
        headers: input.headers ?? {},
      })
      .onConflict(["source_service", "event_id"])
      .ignore()
      .returning("id");
    return rows.length === 1;
  }

  public async publish(input: {
    tenantId: string;
    eventId: string;
    eventType: string;
    aggregateType: string;
    aggregateId: string;
    payload: object;
    headers?: object;
  }): Promise<void> {
    await this.transaction("auth_customer_outbox_events").insert({
      tenant_id: input.tenantId,
      event_id: input.eventId,
      event_type: input.eventType,
      aggregate_type: input.aggregateType,
      aggregate_id: input.aggregateId,
      payload: input.payload,
      headers: input.headers ?? {},
    });
  }
}
