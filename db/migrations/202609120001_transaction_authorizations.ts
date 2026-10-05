import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable("transaction_authorizations")) return;
  await knex.raw(`
    CREATE TABLE transaction_authorizations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id uuid NOT NULL,
      customer_id uuid NOT NULL REFERENCES customer_profiles(id),
      command_type varchar(80) NOT NULL,
      resource_id uuid NOT NULL,
      request_hash char(64) NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
      authorization_method varchar(30) NOT NULL CHECK (authorization_method IN ('transaction_pin','biometric')),
      token_hash char(64) NOT NULL,
      issue_idempotency_key varchar(255) NOT NULL,
      status varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','CONSUMED','REVOKED')),
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz,
      consumed_by_service varchar(100),
      consumption_idempotency_key varchar(255),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, token_hash),
      UNIQUE (tenant_id, issue_idempotency_key),
      CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
      CHECK (expires_at > created_at)
    );
    ALTER TABLE transaction_authorizations ENABLE ROW LEVEL SECURITY;
    ALTER TABLE transaction_authorizations FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON transaction_authorizations
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    CREATE UNIQUE INDEX uq_transaction_authorization_consumption
      ON transaction_authorizations (tenant_id, consumption_idempotency_key)
      WHERE consumption_idempotency_key IS NOT NULL;
    CREATE INDEX idx_transaction_authorization_active
      ON transaction_authorizations (tenant_id, customer_id, expires_at)
      WHERE status = 'ACTIVE';
    REVOKE ALL ON transaction_authorizations FROM parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly;
    GRANT SELECT, INSERT, UPDATE ON transaction_authorizations TO parc_auth_customer_runtime;
    GRANT SELECT, INSERT, UPDATE ON transaction_authorizations TO parc_auth_customer_worker;
    GRANT SELECT ON transaction_authorizations TO parc_auth_customer_readonly;
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Transaction-authorization migration requires a reviewed forward fix",
  );
}
