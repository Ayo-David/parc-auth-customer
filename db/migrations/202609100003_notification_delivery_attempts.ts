import type { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable("notification_delivery_attempts")) return;
  await knex.raw(`
    CREATE TABLE notification_delivery_attempts (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      tenant_id uuid NOT NULL,
      notification_id uuid NOT NULL REFERENCES notifications(id),
      channel notification_channel NOT NULL,
      provider_name varchar(100) NOT NULL,
      provider_configuration_version varchar(100) NOT NULL,
      target_hash varchar(128) NOT NULL,
      hash_key_id varchar(100) NOT NULL,
      attempt_number integer NOT NULL CHECK (attempt_number > 0),
      status varchar(30) NOT NULL CHECK (status IN ('PROCESSING','SENT','DELIVERED','RETRYABLE','FAILED')),
      provider_reference varchar(255),
      failure_code varchar(100),
      response_metadata jsonb NOT NULL DEFAULT '{}',
      started_at timestamptz NOT NULL DEFAULT now(),
      completed_at timestamptz,
      next_retry_at timestamptz,
      metadata_retain_until timestamptz NOT NULL,
      legal_hold boolean NOT NULL DEFAULT false,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (tenant_id, notification_id, target_hash, attempt_number),
      CHECK (
        (status = 'PROCESSING' AND completed_at IS NULL) OR
        (status <> 'PROCESSING' AND completed_at IS NOT NULL)
      ),
      CHECK ((status = 'RETRYABLE' AND next_retry_at IS NOT NULL) OR status <> 'RETRYABLE')
    );
    ALTER TABLE notification_delivery_attempts ENABLE ROW LEVEL SECURITY;
    ALTER TABLE notification_delivery_attempts FORCE ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation_policy ON notification_delivery_attempts
      TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly
      USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
    CREATE INDEX idx_notification_attempt_retry
      ON notification_delivery_attempts (tenant_id, status, next_retry_at)
      WHERE status = 'RETRYABLE';
    CREATE INDEX idx_notification_attempt_history
      ON notification_delivery_attempts (tenant_id, notification_id, created_at DESC);
    REVOKE ALL ON notification_delivery_attempts FROM parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly;
    GRANT SELECT ON notification_delivery_attempts TO parc_auth_customer_runtime;
    GRANT SELECT, INSERT, UPDATE, DELETE ON notification_delivery_attempts TO parc_auth_customer_worker;
    GRANT SELECT ON notification_delivery_attempts TO parc_auth_customer_readonly;

    CREATE FUNCTION reject_completed_notification_attempt_mutation() RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN
      IF OLD.status <> 'PROCESSING' AND NOT (
        current_setting('app.retention_maintenance', true) = 'true' AND
        OLD.legal_hold = false AND
        OLD.metadata_retain_until <= now() AND
        (TG_OP = 'DELETE' OR (
          NEW.id = OLD.id AND NEW.tenant_id = OLD.tenant_id AND
          NEW.notification_id = OLD.notification_id AND NEW.status = OLD.status AND
          NEW.provider_reference IS NULL AND NEW.failure_code IS NULL AND
          NEW.response_metadata = '{}'::jsonb
        ))
      ) THEN
        RAISE EXCEPTION 'Completed notification delivery attempts are append-only';
      END IF;
      IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
      RETURN NEW;
    END $fn$;
    CREATE TRIGGER trg_notification_attempt_immutable
      BEFORE UPDATE OR DELETE ON notification_delivery_attempts
      FOR EACH ROW EXECUTE FUNCTION reject_completed_notification_attempt_mutation();
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "Notification delivery-attempt migration requires a reviewed forward fix",
  );
}
