import type { Knex } from "knex";

/**
 * Transaction authorizations are keyed by the customer-profile ID carried as
 * the access-token subject. Databases that ran the original migration while it
 * still referenced users(id) are converged here; fresh databases are a no-op.
 */
export async function up(knex: Knex): Promise<void> {
  const { rows } = await knex.raw<{ rows: unknown[] }>(`
    SELECT 1 FROM pg_constraint
    WHERE conname = 'transaction_authorizations_customer_id_fkey'
      AND confrelid = 'customer_profiles'::regclass
  `);
  if (rows.length > 0) return;
  // Validating a foreign key is refused while row-level security could hide
  // rows from the checking role, and FORCE applies RLS to the non-superuser
  // table owner that runs migrations. Lift FORCE only inside this migration's
  // transaction.
  await knex.raw(`
    ALTER TABLE transaction_authorizations NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE customer_profiles NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE transaction_authorizations
      DROP CONSTRAINT IF EXISTS transaction_authorizations_customer_id_fkey;
    ALTER TABLE transaction_authorizations
      ADD CONSTRAINT transaction_authorizations_customer_id_fkey
      FOREIGN KEY (customer_id) REFERENCES customer_profiles(id);
    ALTER TABLE customer_profiles FORCE ROW LEVEL SECURITY;
    ALTER TABLE transaction_authorizations FORCE ROW LEVEL SECURITY;
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Transaction-authorization customer key requires a reviewed forward fix",
  );
}
