import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasColumn("user_passkeys", "subject_id")) return;
  await knex.raw(`
    ALTER TABLE user_passkeys
      DROP CONSTRAINT fk_user_passkeys_user,
      ALTER COLUMN tenant_id DROP NOT NULL,
      ALTER COLUMN user_id DROP NOT NULL,
      ADD COLUMN subject_id uuid,
      ADD COLUMN subject_type varchar(30) NOT NULL DEFAULT 'CUSTOMER',
      ADD COLUMN scope_type varchar(20) NOT NULL DEFAULT 'TENANT',
      ADD CONSTRAINT user_passkeys_subject_type_check CHECK (subject_type IN ('CUSTOMER', 'ADMINISTRATOR')),
      ADD CONSTRAINT user_passkeys_scope_type_check CHECK (scope_type IN ('TENANT', 'PLATFORM'));
    UPDATE user_passkeys SET subject_id = user_id;
    ALTER TABLE user_passkeys
      ALTER COLUMN subject_id SET NOT NULL,
      ADD CONSTRAINT fk_user_passkeys_customer_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      ADD CONSTRAINT user_passkeys_subject_ownership_check CHECK (
        (subject_type = 'CUSTOMER' AND scope_type = 'TENANT' AND tenant_id IS NOT NULL AND user_id = subject_id)
        OR
        (subject_type = 'ADMINISTRATOR' AND user_id IS NULL AND (
          (scope_type = 'TENANT' AND tenant_id IS NOT NULL)
          OR (scope_type = 'PLATFORM' AND tenant_id IS NULL)
        ))
      );
    DROP INDEX idx_user_passkeys_user;
    CREATE INDEX idx_user_passkeys_subject
      ON user_passkeys(subject_type, scope_type, tenant_id, subject_id)
      WHERE deleted_at IS NULL;

    DROP POLICY tenant_isolation_policy ON user_passkeys;
    CREATE POLICY tenant_isolation_policy ON user_passkeys
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
    DROP POLICY tenant_isolation_policy ON user_passkeys;
    CREATE POLICY tenant_isolation_policy ON user_passkeys
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    DROP INDEX IF EXISTS idx_user_passkeys_subject;
    ALTER TABLE user_passkeys
      DROP CONSTRAINT user_passkeys_subject_ownership_check,
      DROP CONSTRAINT fk_user_passkeys_customer_user,
      DROP CONSTRAINT user_passkeys_scope_type_check,
      DROP CONSTRAINT user_passkeys_subject_type_check,
      DROP COLUMN scope_type,
      DROP COLUMN subject_type,
      DROP COLUMN subject_id;
    ALTER TABLE user_passkeys
      ALTER COLUMN tenant_id SET NOT NULL,
      ALTER COLUMN user_id SET NOT NULL,
      ADD CONSTRAINT fk_user_passkeys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    CREATE INDEX idx_user_passkeys_user ON user_passkeys(user_id) WHERE deleted_at IS NULL;
  `);
}
