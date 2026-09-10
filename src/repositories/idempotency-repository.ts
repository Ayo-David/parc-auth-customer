import type { Knex } from "knex";

export interface IdempotencyRecord {
  id: string;
  tenant_id: string;
  idempotency_key: string;
  operation: string;
  request_hash: string;
  status: "PROCESSING" | "COMPLETED" | "FAILED";
  response_code: number | null;
  response_body: unknown;
  expires_at: Date;
}

export class IdempotencyRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async claim(input: {
    tenantId: string;
    key: string;
    operation: string;
    requestHash: string;
    expiresAt: Date;
  }): Promise<{ created: boolean; record: IdempotencyRecord }> {
    const inserted = await this.transaction<IdempotencyRecord>(
      "idempotency_keys",
    )
      .insert({
        tenant_id: input.tenantId,
        idempotency_key: input.key,
        operation: input.operation,
        request_hash: input.requestHash,
        expires_at: input.expiresAt,
      })
      .onConflict(["tenant_id", "operation", "idempotency_key"])
      .ignore()
      .returning("*");
    const record =
      inserted[0] ??
      (await this.transaction<IdempotencyRecord>("idempotency_keys")
        .where({
          tenant_id: input.tenantId,
          operation: input.operation,
          idempotency_key: input.key,
        })
        .first());
    if (!record) throw new Error("Idempotency claim returned no record");
    if (record.request_hash !== input.requestHash)
      throw new Error("IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST");
    return { created: inserted.length === 1, record };
  }

  public async complete(input: {
    tenantId: string;
    key: string;
    operation: string;
    responseCode: number;
    responseBody: object;
  }): Promise<void> {
    const updated = await this.transaction("idempotency_keys")
      .where({
        tenant_id: input.tenantId,
        idempotency_key: input.key,
        operation: input.operation,
        status: "PROCESSING",
      })
      .update({
        status: "COMPLETED",
        response_code: input.responseCode,
        response_body: input.responseBody,
        completed_at: this.transaction.fn.now(),
      });
    if (updated !== 1) throw new Error("Idempotency completion failed");
  }
}
