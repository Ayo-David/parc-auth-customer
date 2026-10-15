import type { Knex } from "knex";

/**
 * The BVN a customer verified at onboarding, kept so Payment can open their
 * Paystack dedicated account without asking for it again. Only AES-256-GCM
 * ciphertext is stored, bound to tenant + customer + type so a row can't be
 * copied onto another customer; access is limited to the runtime and worker
 * roles, never the readonly reporting role.
 */
export async function up(knex: Knex): Promise<void> {
  await knex.raw(`
    CREATE TABLE customer_identity_numbers (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id uuid NOT NULL,
      customer_id uuid NOT NULL REFERENCES customer_profiles(id) ON DELETE CASCADE,
      identity_type varchar(10) NOT NULL CHECK (identity_type IN ('BVN', 'NIN')),
      ciphertext text NOT NULL,
      iv varchar(32) NOT NULL,
      auth_tag varchar(32) NOT NULL,
      key_id varchar(100) NOT NULL,
      verification_id uuid NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT uq_customer_identity_number UNIQUE (tenant_id, customer_id, identity_type)
    );

    CREATE TRIGGER trg_customer_identity_numbers_updated_at
      BEFORE UPDATE ON customer_identity_numbers
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    CREATE TRIGGER trg_customer_identity_numbers_tenant_guard
      BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON customer_identity_numbers
      FOR EACH ROW EXECUTE FUNCTION enforce_parent_tenant('customer_profiles', 'id', 'customer_id');

    ALTER TABLE customer_identity_numbers ENABLE ROW LEVEL SECURITY;
    ALTER TABLE customer_identity_numbers FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON customer_identity_numbers
      TO parc_auth_customer_runtime, parc_auth_customer_worker
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

    GRANT SELECT, INSERT, UPDATE ON customer_identity_numbers
      TO parc_auth_customer_runtime, parc_auth_customer_worker;
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw("DROP TABLE IF EXISTS customer_identity_numbers");
}
