# Auth & Customer migration baseline plan

Date: 2026-09-08

## Decision

Use `db/schema/current.sql` as the exact clean-database `0001` baseline. The initial pre-readiness snapshot was proven byte-identical to the disposable local database before the approved upgrade. The current snapshot represents the approved post-migration schema and deliberately excludes Knex bookkeeping tables. Do not use the empty legacy file at `database/baseline/02_auth_customer.sql`.

For legacy databases, the baseline migration requires the separately verified pre-readiness SHA-256 and the second migration applies the approved corrections. For clean databases, the baseline restores the current approved schema and the second migration detects that state and exits safely.

## Proposed files

After schema-gap approval and during A-01/P0-08 implementation:

- `db/migrations/202609080001_initial_auth_customer.ts`
- `db/migrations/sql/202609080001_initial_auth_customer.sql` — exact baseline DDL
- `db/migrations/202609080002_<approved_change>.ts` — one or more separate forward migrations
- `knexfile.ts`
- `scripts/check-schema-drift.ts`
- `scripts/verify-migration-baseline.ts`

## Clean database procedure

1. Create an empty PostgreSQL database with the approved runtime encoding and extensions available.
2. Run Knex migrations using a migration-only role.
3. Assert 43 baseline tables, required enums/functions/triggers/indexes, RLS state, and policies.
4. Apply approved follow-up migrations.
5. Generate a schema-only dump using stable flags and compare it with `db/schema/current.sql`.
6. Run tenant-isolation, owner-bypass, credential, session, idempotency, and inbox/outbox integration tests.

## Existing disposable database procedure

1. Verify its normalized schema hash matches the baseline hash.
2. Insert the Knex baseline migration record without replaying baseline DDL only when the hash is exact.
3. Run pending approved forward migrations normally.
4. Regenerate the checked-in snapshot and run drift checks.

If the hash differs, stop. Never stamp an unknown database as migrated.

## Deployment safety

- Take a schema and data backup before any non-disposable deployment.
- Use explicit statement and lock timeouts for follow-up migrations.
- Validate row counts, nullability, uniqueness, money conversions and cryptographic evidence before switching reads/writes.
- Prefer expand/backfill/validate/contract migrations for populated tables.
- Do not silently reverse a financially or legally consequential migration. Use a reviewed forward fix.
- `down` for the initial baseline must refuse destructive rollback unless an explicitly disposable environment guard is present.

## Current status

The guarded executable baseline and approved production-readiness migration are implemented. Both migrations pass on a clean disposable database. The existing local database was accepted only with the previously verified baseline SHA-256, migrated, and used to regenerate `db/schema/current.sql`.
