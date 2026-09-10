import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable("kyc_tier_versions")) return;
  await knex.raw(`
    ALTER TABLE kyc_tiers RENAME TO kyc_tier_standards;
    CREATE TABLE kyc_tier_versions (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
      standard_tier_id uuid REFERENCES kyc_tier_standards(id), code varchar(30) NOT NULL,
      name varchar(100) NOT NULL, version integer NOT NULL CHECK (version > 0),
      status varchar(20) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','PUBLISHED','RETIRED')),
      requirements jsonb NOT NULL DEFAULT '{}',
      daily_transaction_limit_minor bigint NOT NULL CHECK (daily_transaction_limit_minor >= 0),
      balance_ceiling_minor bigint CHECK (balance_ceiling_minor IS NULL OR balance_ceiling_minor >= 0),
      currency char(3) NOT NULL DEFAULT 'NGN' CHECK (currency ~ '^[A-Z]{3}$'),
      effective_from timestamptz, published_at timestamptz, published_by uuid, approval_id uuid,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, code, version),
      CHECK ((status = 'DRAFT') OR (published_at IS NOT NULL AND approval_id IS NOT NULL))
    );
    ALTER TABLE kyc_tier_versions ENABLE ROW LEVEL SECURITY;
    ALTER TABLE kyc_tier_versions FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON kyc_tier_versions
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    CREATE INDEX idx_kyc_tier_versions_tenant_status ON kyc_tier_versions (tenant_id, status);
    ALTER TABLE customer_kyc_tiers DROP CONSTRAINT fk_customer_kyc_tier_definition;
    ALTER TABLE customer_kyc_tiers DROP COLUMN kyc_tier_id;
    ALTER TABLE customer_kyc_tiers ADD COLUMN kyc_tier_version_id uuid NOT NULL REFERENCES kyc_tier_versions(id);
    CREATE INDEX idx_customer_kyc_tier_version ON customer_kyc_tiers (kyc_tier_version_id);

    CREATE FUNCTION prevent_published_record_mutation() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN IF OLD.status = 'PUBLISHED' THEN RAISE EXCEPTION 'Published records are immutable'; END IF; RETURN NEW; END $fn$;
    CREATE TRIGGER trg_kyc_tier_version_immutable BEFORE UPDATE OR DELETE ON kyc_tier_versions
      FOR EACH ROW EXECUTE FUNCTION prevent_published_record_mutation();

    ALTER TABLE referral_programs ADD COLUMN referrer_reward_amount_minor bigint;
    ALTER TABLE referral_programs ADD COLUMN referee_reward_amount_minor bigint;
    UPDATE referral_programs SET referrer_reward_amount_minor = round(referrer_reward_amount * 100)::bigint,
      referee_reward_amount_minor = round(referee_reward_amount * 100)::bigint;
    ALTER TABLE referral_programs DROP COLUMN referrer_reward_amount;
    ALTER TABLE referral_programs DROP COLUMN referee_reward_amount;
    ALTER TABLE referral_programs ADD CHECK (referrer_reward_amount_minor IS NULL OR referrer_reward_amount_minor >= 0);
    ALTER TABLE referral_programs ADD CHECK (referee_reward_amount_minor IS NULL OR referee_reward_amount_minor >= 0);
    ALTER TABLE referral_rewards ADD COLUMN amount_minor bigint;
    UPDATE referral_rewards SET amount_minor = round(amount * 100)::bigint;
    ALTER TABLE referral_rewards ALTER COLUMN amount_minor SET NOT NULL;
    ALTER TABLE referral_rewards DROP COLUMN amount;
    ALTER TABLE referral_rewards ADD CHECK (amount_minor > 0);
    ALTER TABLE referral_reward_transactions ADD COLUMN amount_minor bigint;
    UPDATE referral_reward_transactions SET amount_minor = round(amount * 100)::bigint;
    ALTER TABLE referral_reward_transactions ALTER COLUMN amount_minor SET NOT NULL;
    ALTER TABLE referral_reward_transactions DROP COLUMN amount;
    ALTER TABLE referral_reward_transactions ADD CHECK (amount_minor > 0);

    ALTER TABLE customer_documents ADD COLUMN document_number_masked varchar(64),
      ADD COLUMN document_hash_key_id varchar(100), ADD COLUMN identity_vault_reference text,
      ADD COLUMN consent_id uuid REFERENCES user_consents(id);
    CREATE TABLE identity_verification_evidence (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
      verification_id uuid NOT NULL REFERENCES kyc_verifications(id),
      consent_id uuid NOT NULL REFERENCES user_consents(id), identifier_type verification_type NOT NULL,
      identifier_masked varchar(64) NOT NULL, identifier_hash varchar(128) NOT NULL,
      hash_key_id varchar(100) NOT NULL, provider_reference varchar(255) NOT NULL,
      provider_configuration_version varchar(100) NOT NULL, result_digest varchar(128) NOT NULL,
      result_signature text NOT NULL, signing_key_id varchar(100) NOT NULL,
      identity_vault_reference text, verified_at timestamptz NOT NULL, retain_until timestamptz NOT NULL,
      legal_hold boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, identifier_type, identifier_hash, provider_reference)
    );
    ALTER TABLE identity_verification_evidence ENABLE ROW LEVEL SECURITY;
    ALTER TABLE identity_verification_evidence FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON identity_verification_evidence
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    ALTER TABLE kyc_verifications ADD COLUMN consent_id uuid REFERENCES user_consents(id),
      ADD COLUMN provider_configuration_version varchar(100);
    ALTER TABLE aml_screening_checks ADD COLUMN provider_configuration_version varchar(100);

    ALTER TABLE user_sessions ADD COLUMN token_family_id uuid NOT NULL DEFAULT gen_random_uuid(),
      ADD COLUMN rotation_sequence integer NOT NULL DEFAULT 0 CHECK (rotation_sequence >= 0),
      ADD COLUMN replaced_by_session_id uuid REFERENCES user_sessions(id), ADD COLUMN reuse_detected_at timestamptz,
      ADD COLUMN compromised_at timestamptz, ADD COLUMN audience varchar(100) NOT NULL DEFAULT 'parc-mobile',
      ADD COLUMN subject_type varchar(30) NOT NULL DEFAULT 'CUSTOMER' CHECK (subject_type IN ('CUSTOMER','ADMINISTRATOR')),
      ADD COLUMN authentication_methods text[] NOT NULL DEFAULT '{}', ADD COLUMN mfa_verified_at timestamptz,
      ADD COLUMN idle_expires_at timestamptz;
    CREATE UNIQUE INDEX uq_user_session_family_rotation ON user_sessions(token_family_id, rotation_sequence);
    CREATE INDEX idx_user_session_family_active ON user_sessions(tenant_id, token_family_id) WHERE revoked_at IS NULL;
    CREATE TABLE authentication_challenges (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid,
      challenge_hash varchar(128) NOT NULL, challenge_type varchar(30) NOT NULL, purpose varchar(50) NOT NULL,
      attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0), max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
      expires_at timestamptz NOT NULL, consumed_at timestamptz, result varchar(30), created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, challenge_hash)
    );
    ALTER TABLE authentication_challenges ENABLE ROW LEVEL SECURITY;
    ALTER TABLE authentication_challenges FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON authentication_challenges
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    CREATE INDEX idx_auth_challenge_expiry ON authentication_challenges(expires_at) WHERE consumed_at IS NULL;

    ALTER TABLE notifications ADD COLUMN classification varchar(30) NOT NULL DEFAULT 'NON_FINANCIAL'
      CHECK (classification IN ('NON_FINANCIAL','FINANCIAL','CONTRACTUAL','KYC','SECURITY','COMPLAINT')),
      ADD COLUMN content_retain_until timestamptz, ADD COLUMN metadata_retain_until timestamptz,
      ADD COLUMN legal_hold boolean NOT NULL DEFAULT false;
    ALTER TABLE provider_webhook_events ADD COLUMN retain_until timestamptz NOT NULL DEFAULT (now() + interval '30 days');
    ALTER TABLE login_attempts ADD COLUMN retain_until timestamptz NOT NULL DEFAULT (now() + interval '24 months');
    ALTER TABLE auth_audit_events ADD COLUMN retain_until timestamptz, ADD COLUMN legal_hold boolean NOT NULL DEFAULT false;
    ALTER TABLE user_consents ADD COLUMN purpose varchar(150), ADD COLUMN channel varchar(30),
      ADD COLUMN policy_uri text, ADD COLUMN evidence_digest varchar(128);
    ALTER TABLE user_2fa_methods ADD COLUMN encryption_key_id varchar(100);
    ALTER TABLE users ADD COLUMN phone_normalized varchar(30), ADD COLUMN email_normalized varchar(255),
      ADD CONSTRAINT users_customer_boundary_chk CHECK (user_type <> 'STAFF');
    CREATE UNIQUE INDEX uq_users_tenant_phone_normalized ON users(tenant_id, phone_normalized)
      WHERE phone_normalized IS NOT NULL AND deleted_at IS NULL;
    CREATE UNIQUE INDEX uq_users_tenant_email_normalized ON users(tenant_id, email_normalized)
      WHERE email_normalized IS NOT NULL AND deleted_at IS NULL;

    CREATE FUNCTION reject_auth_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN RAISE EXCEPTION 'Auth audit events are append-only'; END $fn$;
    CREATE TRIGGER trg_auth_audit_immutable BEFORE UPDATE OR DELETE ON auth_audit_events
      FOR EACH ROW EXECUTE FUNCTION reject_auth_audit_mutation();
    DROP POLICY IF EXISTS aml_profiles_tenant_policy ON aml_profiles;
    DROP POLICY IF EXISTS customer_addresses_tenant_policy ON customer_addresses;
    DROP POLICY IF EXISTS customer_documents_tenant_policy ON customer_documents;
    DROP POLICY IF EXISTS customer_profiles_tenant_policy ON customer_profiles;
    DROP POLICY IF EXISTS customer_risk_tenant_policy ON customer_risk_profiles;
    DROP POLICY IF EXISTS fraud_flags_tenant_policy ON fraud_flags;
    DROP POLICY IF EXISTS kyc_profiles_tenant_policy ON kyc_profiles;
    DROP POLICY IF EXISTS notifications_tenant_policy ON notifications;
    DROP POLICY IF EXISTS referral_rewards_tenant_policy ON referral_rewards;
    DROP POLICY IF EXISTS referrals_tenant_policy ON referrals;
    DROP POLICY IF EXISTS users_tenant_policy ON users;

    DO $roles$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_runtime') THEN CREATE ROLE parc_auth_customer_runtime NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_worker') THEN CREATE ROLE parc_auth_customer_worker NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_readonly') THEN CREATE ROLE parc_auth_customer_readonly NOLOGIN NOBYPASSRLS; END IF;
    END $roles$;
    GRANT USAGE ON SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO parc_auth_customer_readonly;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker;
    DO $policies$ DECLARE target record; BEGIN
      FOR target IN SELECT tablename FROM pg_policies WHERE schemaname = 'public' AND policyname = 'tenant_isolation_policy'
      LOOP EXECUTE format('ALTER POLICY tenant_isolation_policy ON public.%I TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly', target.tablename); END LOOP;
    END $policies$;
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Production-readiness migration requires a reviewed forward fix",
  );
}
