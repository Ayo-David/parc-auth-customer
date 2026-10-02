import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  // A clean bootstrap executes the current canonical snapshot first. That
  // snapshot already includes this table; older installations still need the
  // forward migration below.
  if (await knex.schema.hasTable("customer_onboarding_sessions")) return;

  await knex.raw(`
    ALTER TYPE credential_type ADD VALUE IF NOT EXISTS 'LOGIN_PASSCODE';

    ALTER TABLE customer_addresses
      ADD COLUMN IF NOT EXISTS lga varchar(100),
      ADD COLUMN IF NOT EXISTS area varchar(150),
      ADD COLUMN IF NOT EXISTS landmark varchar(255);

    ALTER TABLE customer_profiles
      ADD COLUMN IF NOT EXISTS annual_income_band varchar(80),
      ADD COLUMN IF NOT EXISTS has_other_income boolean;

    CREATE TABLE customer_onboarding_sessions (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id uuid NOT NULL,
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      customer_id uuid NOT NULL REFERENCES customer_profiles(id) ON DELETE CASCADE,
      status varchar(30) NOT NULL DEFAULT 'IN_PROGRESS'
        CHECK (status IN ('IN_PROGRESS', 'COMPLETED', 'EXPIRED')),
      current_step varchar(40) NOT NULL DEFAULT 'PHONE_VERIFICATION',
      completed_steps jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(completed_steps) = 'array'),
      onboarding_version varchar(30) NOT NULL DEFAULT 'mobile-v1',
      expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
      completed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT customer_onboarding_completion_check CHECK (
        (status = 'COMPLETED' AND completed_at IS NOT NULL)
        OR (status <> 'COMPLETED' AND completed_at IS NULL)
      )
    );

    CREATE UNIQUE INDEX uq_customer_onboarding_active_user
      ON customer_onboarding_sessions (tenant_id, user_id)
      WHERE status = 'IN_PROGRESS';
    CREATE INDEX idx_customer_onboarding_resume
      ON customer_onboarding_sessions (tenant_id, user_id, updated_at DESC);

    CREATE TRIGGER trg_customer_onboarding_updated_at
      BEFORE UPDATE ON customer_onboarding_sessions
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
    CREATE TRIGGER trg_customer_onboarding_user_tenant_guard
      BEFORE INSERT OR UPDATE OF tenant_id, user_id ON customer_onboarding_sessions
      FOR EACH ROW EXECUTE FUNCTION enforce_parent_tenant('users', 'id', 'user_id');
    CREATE TRIGGER trg_customer_onboarding_customer_tenant_guard
      BEFORE INSERT OR UPDATE OF tenant_id, customer_id ON customer_onboarding_sessions
      FOR EACH ROW EXECUTE FUNCTION enforce_parent_tenant('customer_profiles', 'id', 'customer_id');

    ALTER TABLE customer_onboarding_sessions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE customer_onboarding_sessions FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON customer_onboarding_sessions
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

    GRANT SELECT, INSERT, UPDATE ON customer_onboarding_sessions
      TO parc_auth_customer_runtime, parc_auth_customer_worker;
    GRANT SELECT ON customer_onboarding_sessions TO parc_auth_customer_readonly;

    COMMENT ON TYPE credential_type IS
      'PASSWORD and LOGIN_PASSCODE authenticate sessions; PIN authorizes financial transactions; PASSKEY is WebAuthn.';
    COMMENT ON TABLE customer_onboarding_sessions IS
      'Durable, resumable customer onboarding progress; authoritative identity data remains in its owning tables.';
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Mobile-onboarding migration requires a reviewed forward fix",
  );
}
