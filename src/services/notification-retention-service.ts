import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";

export interface NotificationRetentionResult {
  contentRedacted: number;
  metadataRedacted: number;
  attemptsDeleted: number;
}

export class NotificationRetentionService {
  public constructor(private readonly database: Knex) {}

  public run(tenantId: string): Promise<NotificationRetentionResult> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        await transaction.raw(
          "SELECT set_config('app.retention_maintenance', 'true', true)",
        );
        const contentRedacted = await transaction("notifications")
          .where({ tenant_id: tenantId, legal_hold: false })
          .where("content_retain_until", "<=", transaction.fn.now())
          .whereNot({ body: "[CONTENT_REDACTED]" })
          .update({
            subject: null,
            body: "[CONTENT_REDACTED]",
            updated_at: transaction.fn.now(),
          });
        const metadataRedacted = await transaction("notifications")
          .where({ tenant_id: tenantId, legal_hold: false })
          .where("metadata_retain_until", "<=", transaction.fn.now())
          .where((builder) =>
            builder
              .whereNotNull("recipient")
              .orWhereNotNull("provider_reference")
              .orWhereNotNull("failure_reason")
              .orWhereRaw("metadata <> '{}'::jsonb"),
          )
          .update({
            recipient: null,
            provider_reference: null,
            failure_reason: null,
            metadata: {},
            updated_at: transaction.fn.now(),
          });
        const attemptsDeleted = await transaction(
          "notification_delivery_attempts",
        )
          .where({ tenant_id: tenantId, legal_hold: false })
          .where("metadata_retain_until", "<=", transaction.fn.now())
          .delete();
        return { contentRedacted, metadataRedacted, attemptsDeleted };
      },
    );
  }
}
