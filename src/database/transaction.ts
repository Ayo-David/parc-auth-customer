import type { Knex } from "knex";
import { z } from "zod";

const tenantIdSchema = z.string().uuid();

export type TenantTransactionWork<T> = (
  transaction: Knex.Transaction,
) => Promise<T>;

export async function withTenantTransaction<T>(
  database: Knex,
  tenantId: string,
  work: TenantTransactionWork<T>,
): Promise<T> {
  const validatedTenantId = tenantIdSchema.parse(tenantId);
  return database.transaction(async (transaction) => {
    await transaction.raw("SELECT set_config('app.tenant_id', ?, true)", [
      validatedTenantId,
    ]);
    return work(transaction);
  });
}

export async function withAuthScopeTransaction<T>(
  database: Knex,
  tenantId: string | null,
  scope: "TENANT" | "PLATFORM",
  work: TenantTransactionWork<T>,
): Promise<T> {
  if (scope === "TENANT") {
    if (!tenantId) throw new Error("Tenant scope requires a tenant ID");
    return withTenantTransaction(database, tenantId, work);
  }
  if (tenantId) throw new Error("Platform scope cannot carry a tenant ID");
  return database.transaction(async (transaction) => {
    await transaction.raw(
      "SELECT set_config('app.platform_scope', 'true', true)",
    );
    return work(transaction);
  });
}
