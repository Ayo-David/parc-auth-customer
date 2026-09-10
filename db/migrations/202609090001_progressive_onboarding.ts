import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.raw(`
    ALTER TABLE customer_profiles ALTER COLUMN first_name DROP NOT NULL;
    ALTER TABLE customer_profiles ALTER COLUMN last_name DROP NOT NULL;
    ALTER TABLE user_consents ADD COLUMN IF NOT EXISTS consent_document_id uuid;
    ALTER TABLE user_consents ALTER COLUMN consent_document_id SET NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_user_consents_document
      ON user_consents (tenant_id, consent_document_id);
  `);
  await knex.raw(`
    COMMENT ON COLUMN user_consents.consent_document_id IS
      'External immutable consent-document identifier owned by Tenant Admin; intentionally no cross-database foreign key';
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Progressive-onboarding migration requires a reviewed forward fix",
  );
}
