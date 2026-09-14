import { Pool } from "pg";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;

integrationTest("enforces approved Auth schema invariants", async () => {
  const pool = new Pool({ connectionString: databaseUrl });
  try {
    const money = await pool.query<{ column_name: string; data_type: string }>(
      `SELECT column_name, data_type FROM information_schema.columns
       WHERE table_schema = 'public'
         AND table_name IN ('referral_programs', 'referral_rewards', 'referral_reward_transactions')
         AND column_name LIKE '%amount%'`,
    );
    expect(money.rows).toHaveLength(4);
    expect(
      money.rows.every(
        ({ column_name, data_type }) =>
          column_name.endsWith("_minor") && data_type === "bigint",
      ),
    ).toBe(true);

    const rls = await pool.query<{ forced: string; total: string }>(
      `SELECT count(*) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity)::text AS forced,
              count(*)::text AS total
       FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN information_schema.columns col ON col.table_schema = n.nspname
         AND col.table_name = c.relname AND col.column_name = 'tenant_id'
       WHERE n.nspname = 'public' AND c.relkind = 'r'`,
    );
    expect(rls.rows[0]).toEqual({
      forced: rls.rows[0]?.total,
      total: rls.rows[0]?.total,
    });

    const required = await pool.query<{ table_name: string }>(
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name IN
         ('kyc_tier_versions', 'identity_verification_evidence', 'authentication_challenges', 'notification_delivery_attempts', 'transaction_authorizations')`,
    );
    expect(required.rows.map(({ table_name }) => table_name).sort()).toEqual([
      "authentication_challenges",
      "identity_verification_evidence",
      "kyc_tier_versions",
      "notification_delivery_attempts",
      "transaction_authorizations",
    ]);

    const onboardingColumns = await pool.query<{
      table_name: string;
      column_name: string;
      is_nullable: string;
    }>(
      `SELECT table_name, column_name, is_nullable
       FROM information_schema.columns
       WHERE table_schema = 'public' AND
         ((table_name = 'customer_profiles' AND column_name IN ('first_name', 'last_name')) OR
          (table_name = 'user_consents' AND column_name = 'consent_document_id'))
       ORDER BY table_name, column_name`,
    );
    expect(onboardingColumns.rows).toEqual([
      {
        table_name: "customer_profiles",
        column_name: "first_name",
        is_nullable: "YES",
      },
      {
        table_name: "customer_profiles",
        column_name: "last_name",
        is_nullable: "YES",
      },
      {
        table_name: "user_consents",
        column_name: "consent_document_id",
        is_nullable: "NO",
      },
    ]);

    const roles = await pool.query<{
      rolname: string;
      rolsuper: boolean;
      rolbypassrls: boolean;
      rolcanlogin: boolean;
    }>(
      `SELECT rolname, rolsuper, rolbypassrls, rolcanlogin FROM pg_roles
       WHERE rolname IN ('parc_auth_customer_runtime', 'parc_auth_customer_worker', 'parc_auth_customer_readonly')
       ORDER BY rolname`,
    );
    expect(roles.rows).toHaveLength(3);
    expect(
      roles.rows.every(
        ({ rolsuper, rolbypassrls, rolcanlogin }) =>
          !rolsuper && !rolbypassrls && !rolcanlogin,
      ),
    ).toBe(true);
  } finally {
    await pool.end();
  }
});
