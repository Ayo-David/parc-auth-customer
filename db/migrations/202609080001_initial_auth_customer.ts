import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { Knex } from "knex";

export const config = { transaction: false };
const approvedExistingBaselineHash =
  "fc648c48a8f623db1c73fd424892f1deabf0e96581d5fdb548cdf2c7eaf75eec";
const canonicalSnapshotHash =
  "068660861d1735aa44095162a47909bf09455aad7abdec29ac067a11bb7dcbd0";

export async function up(knex: Knex): Promise<void> {
  if (await knex.schema.hasTable("users")) {
    if (
      process.env.APPROVED_EXISTING_BASELINE_SHA256 !==
      approvedExistingBaselineHash
    ) {
      throw new Error(
        "Existing database requires the separately verified approved baseline SHA-256",
      );
    }
    return;
  }
  await knex.raw(`
    DO $roles$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_runtime') THEN CREATE ROLE parc_auth_customer_runtime NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_worker') THEN CREATE ROLE parc_auth_customer_worker NOLOGIN NOBYPASSRLS; END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'parc_auth_customer_readonly') THEN CREATE ROLE parc_auth_customer_readonly NOLOGIN NOBYPASSRLS; END IF;
    END $roles$;
  `);
  const snapshot = fileURLToPath(
    new URL("../schema/current.sql", import.meta.url),
  );
  const sql = await readFile(snapshot, "utf8");
  const actualHash = createHash("sha256").update(sql).digest("hex");
  if (actualHash !== canonicalSnapshotHash) {
    throw new Error(
      `Auth & Customer schema snapshot hash mismatch: ${actualHash}`,
    );
  }
  await knex.raw(sql);
  await knex.raw("SET search_path TO public");
  await knex.raw(`
    GRANT USAGE ON SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker, parc_auth_customer_readonly;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker;
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO parc_auth_customer_readonly;
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO parc_auth_customer_runtime, parc_auth_customer_worker;
  `);
}

export async function down(): Promise<never> {
  throw new Error(
    "The initial Auth & Customer baseline cannot be rolled back destructively",
  );
}
