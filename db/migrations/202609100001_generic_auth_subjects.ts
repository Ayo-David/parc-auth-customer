import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn("user_sessions", "subject_id")) return;
  await knex.raw(`
    ALTER TABLE user_sessions
      DROP CONSTRAINT fk_user_sessions_user,
      ALTER COLUMN tenant_id DROP NOT NULL,
      ALTER COLUMN user_id DROP NOT NULL,
      ADD COLUMN subject_id uuid,
      ADD COLUMN scope_type varchar(20) NOT NULL DEFAULT 'TENANT',
      ADD COLUMN authorization_version integer,
      ADD CONSTRAINT user_sessions_scope_type_check CHECK (scope_type IN ('TENANT', 'PLATFORM')),
      ADD CONSTRAINT user_sessions_authorization_version_check CHECK (authorization_version IS NULL OR authorization_version >= 1);
    UPDATE user_sessions SET subject_id = user_id;
    ALTER TABLE user_sessions ALTER COLUMN subject_id SET NOT NULL,
      ADD CONSTRAINT fk_user_sessions_customer_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      ADD CONSTRAINT user_sessions_subject_ownership_check CHECK (
        (subject_type = 'CUSTOMER' AND scope_type = 'TENANT' AND tenant_id IS NOT NULL AND user_id = subject_id AND authorization_version IS NULL)
        OR
        (subject_type = 'ADMINISTRATOR' AND user_id IS NULL AND (
          (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
          OR (scope_type = 'PLATFORM' AND tenant_id IS NULL)
        ) AND authorization_version IS NOT NULL)
      );
    CREATE INDEX idx_user_sessions_subject ON user_sessions(subject_type, scope_type, tenant_id, subject_id) WHERE deleted_at IS NULL;

    ALTER TABLE user_2fa_methods
      DROP CONSTRAINT fk_2fa_user,
      ALTER COLUMN tenant_id DROP NOT NULL,
      ALTER COLUMN user_id DROP NOT NULL,
      ADD COLUMN subject_id uuid,
      ADD COLUMN subject_type varchar(30) NOT NULL DEFAULT 'CUSTOMER',
      ADD COLUMN scope_type varchar(20) NOT NULL DEFAULT 'TENANT',
      ADD CONSTRAINT user_2fa_subject_type_check CHECK (subject_type IN ('CUSTOMER', 'ADMINISTRATOR')),
      ADD CONSTRAINT user_2fa_scope_type_check CHECK (scope_type IN ('TENANT', 'PLATFORM'));
    UPDATE user_2fa_methods SET subject_id = user_id;
    ALTER TABLE user_2fa_methods ALTER COLUMN subject_id SET NOT NULL,
      ADD CONSTRAINT fk_2fa_customer_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      ADD CONSTRAINT user_2fa_subject_ownership_check CHECK (
        (subject_type = 'CUSTOMER' AND scope_type = 'TENANT' AND tenant_id IS NOT NULL AND user_id = subject_id)
        OR
        (subject_type = 'ADMINISTRATOR' AND user_id IS NULL AND (
          (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
          OR (scope_type = 'PLATFORM' AND tenant_id IS NULL)
        ))
      );
    DROP INDEX idx_2fa_user;
    CREATE INDEX idx_2fa_subject ON user_2fa_methods(subject_type, scope_type, tenant_id, subject_id) WHERE deleted_at IS NULL;

    ALTER TABLE authentication_challenges
      ALTER COLUMN tenant_id DROP NOT NULL,
      ADD COLUMN subject_id uuid,
      ADD COLUMN subject_type varchar(30),
      ADD COLUMN scope_type varchar(20),
      ADD COLUMN authorization_version integer,
      ADD CONSTRAINT authentication_challenges_subject_type_check CHECK (subject_type IS NULL OR subject_type IN ('CUSTOMER', 'ADMINISTRATOR')),
      ADD CONSTRAINT authentication_challenges_scope_type_check CHECK (scope_type IS NULL OR scope_type IN ('TENANT', 'PLATFORM')),
      ADD CONSTRAINT authentication_challenges_authorization_version_check CHECK (authorization_version IS NULL OR authorization_version >= 1),
      ADD CONSTRAINT authentication_challenges_subject_check CHECK (
        (subject_id IS NULL AND user_id IS NULL AND subject_type IS NULL AND scope_type IS NULL)
        OR
        (subject_id IS NOT NULL AND subject_type = 'CUSTOMER' AND scope_type = 'TENANT' AND tenant_id IS NOT NULL AND user_id = subject_id)
        OR
        (subject_id IS NOT NULL AND subject_type = 'ADMINISTRATOR' AND user_id IS NULL AND (
          (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
          OR (scope_type = 'PLATFORM' AND tenant_id IS NULL)
        ) AND authorization_version IS NOT NULL)
      );
    UPDATE authentication_challenges
      SET subject_id = user_id, subject_type = 'CUSTOMER', scope_type = 'TENANT'
      WHERE user_id IS NOT NULL;
    CREATE INDEX idx_auth_challenge_subject ON authentication_challenges(subject_type, scope_type, tenant_id, subject_id) WHERE consumed_at IS NULL;

    DROP POLICY tenant_isolation_policy ON user_sessions;
    CREATE POLICY tenant_isolation_policy ON user_sessions
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      )
      WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      );
    DROP POLICY tenant_isolation_policy ON user_2fa_methods;
    CREATE POLICY tenant_isolation_policy ON user_2fa_methods
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      )
      WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      );
    DROP POLICY tenant_isolation_policy ON authentication_challenges;
    CREATE POLICY tenant_isolation_policy ON authentication_challenges
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      )
      WITH CHECK (
        tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        OR (tenant_id IS NULL AND scope_type = 'PLATFORM' AND current_setting('app.platform_scope', true) = 'true')
      );
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(`
    DROP POLICY tenant_isolation_policy ON user_sessions;
    CREATE POLICY tenant_isolation_policy ON user_sessions
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    DROP POLICY tenant_isolation_policy ON user_2fa_methods;
    CREATE POLICY tenant_isolation_policy ON user_2fa_methods
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    DROP POLICY tenant_isolation_policy ON authentication_challenges;
    CREATE POLICY tenant_isolation_policy ON authentication_challenges
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

    DROP INDEX IF EXISTS idx_auth_challenge_subject;
    ALTER TABLE authentication_challenges
      DROP CONSTRAINT authentication_challenges_subject_check,
      DROP CONSTRAINT authentication_challenges_authorization_version_check,
      DROP CONSTRAINT authentication_challenges_scope_type_check,
      DROP CONSTRAINT authentication_challenges_subject_type_check,
      DROP COLUMN authorization_version,
      DROP COLUMN scope_type,
      DROP COLUMN subject_type,
      DROP COLUMN subject_id;
    ALTER TABLE authentication_challenges ALTER COLUMN tenant_id SET NOT NULL;

    DROP INDEX IF EXISTS idx_2fa_subject;
    ALTER TABLE user_2fa_methods
      DROP CONSTRAINT user_2fa_subject_ownership_check,
      DROP CONSTRAINT fk_2fa_customer_user,
      DROP CONSTRAINT user_2fa_scope_type_check,
      DROP CONSTRAINT user_2fa_subject_type_check,
      DROP COLUMN scope_type,
      DROP COLUMN subject_type,
      DROP COLUMN subject_id;
    ALTER TABLE user_2fa_methods ALTER COLUMN user_id SET NOT NULL, ALTER COLUMN tenant_id SET NOT NULL,
      ADD CONSTRAINT fk_2fa_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    CREATE INDEX idx_2fa_user ON user_2fa_methods(user_id) WHERE deleted_at IS NULL;

    DROP INDEX IF EXISTS idx_user_sessions_subject;
    ALTER TABLE user_sessions
      DROP CONSTRAINT user_sessions_subject_ownership_check,
      DROP CONSTRAINT fk_user_sessions_customer_user,
      DROP CONSTRAINT user_sessions_authorization_version_check,
      DROP CONSTRAINT user_sessions_scope_type_check,
      DROP COLUMN authorization_version,
      DROP COLUMN scope_type,
      DROP COLUMN subject_id;
    ALTER TABLE user_sessions ALTER COLUMN user_id SET NOT NULL, ALTER COLUMN tenant_id SET NOT NULL,
      ADD CONSTRAINT fk_user_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
  `);
}
