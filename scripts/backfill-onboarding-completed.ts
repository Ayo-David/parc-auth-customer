/**
 * Re-publishes `customer.onboarding.completed.v1` for customers who finished
 * onboarding before Auth started emitting it, so Ledger provisions their
 * wallet account. Safe to re-run: Ledger provisions at most one wallet per
 * customer, and customers who already have the event are skipped.
 *
 *   node --env-file=.env --import tsx scripts/backfill-onboarding-completed.ts <tenant-id> [--dry-run]
 *
 * The events go through the normal outbox, so the outbox publisher must be
 * running (OUTBOX_PUBLISHER_ENABLED with this tenant in OUTBOX_TENANT_IDS).
 */
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { loadConfig } from "../src/config/env.js";
import { createDatabase } from "../src/database/client.js";
import { withTenantTransaction } from "../src/database/transaction.js";
import { publishOnboardingCompleted } from "../src/services/onboarding-service.js";

const [tenantArgument, flag] = process.argv.slice(2);
const tenantId = z.string().uuid("Pass the tenant id").parse(tenantArgument);
const dryRun = flag === "--dry-run";
const database = createDatabase(loadConfig());

try {
  const published = await withTenantTransaction(
    database,
    tenantId,
    async (tx) => {
      const sessions = await tx("customer_onboarding_sessions as s")
        .where({ "s.tenant_id": tenantId, "s.status": "COMPLETED" })
        .whereNotExists(
          tx("auth_customer_outbox_events as e")
            .whereRaw("e.aggregate_id = s.customer_id")
            .where({
              "e.tenant_id": tenantId,
              "e.event_type": "customer.onboarding.completed.v1",
            }),
        )
        .distinct<{ customer_id: string }[]>("s.customer_id");
      if (!dryRun)
        for (const { customer_id: customerId } of sessions)
          await publishOnboardingCompleted(tx, {
            tenantId,
            customerId,
            correlationId: randomUUID(),
          });
      return sessions.length;
    },
  );
  console.log(
    dryRun
      ? `${String(published)} completed customer(s) have no onboarding-completed event yet.`
      : `Queued onboarding-completed events for ${String(published)} customer(s).`,
  );
} finally {
  await database.destroy();
}
