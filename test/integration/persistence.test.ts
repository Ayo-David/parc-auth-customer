import { randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { CredentialRepository } from "../../src/repositories/credential-repository.js";
import { EventRepository } from "../../src/repositories/event-repository.js";
import { IdempotencyRepository } from "../../src/repositories/idempotency-repository.js";
import { SessionRepository } from "../../src/repositories/session-repository.js";
import { UserRepository } from "../../src/repositories/user-repository.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});

afterAll(async () => {
  await database.destroy();
});

integrationTest(
  "isolates tenant repository reads through the runtime role",
  async () => {
    const tenantA = randomUUID();
    const tenantB = randomUUID();
    const phone = "+2348000000001";
    const created = await withTenantTransaction(
      database,
      tenantA,
      async (transaction) => {
        await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
        return new UserRepository(transaction).create({
          tenantId: tenantA,
          phone,
          phoneNormalized: phone,
        });
      },
    );

    const invisible = await withTenantTransaction(
      database,
      tenantB,
      async (transaction) => {
        await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
        return new UserRepository(transaction).findById(created.id);
      },
    );
    expect(invisible).toBeUndefined();

    const visible = await withTenantTransaction(
      database,
      tenantA,
      async (transaction) => {
        await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
        return new UserRepository(transaction).findById(created.id);
      },
    );
    expect(visible?.tenant_id).toBe(tenantA);
    await database("users").where({ id: created.id }).delete();
  },
);

integrationTest(
  "rolls back all work when tenant transaction fails",
  async () => {
    const tenantId = randomUUID();
    const phone = "+2348000000002";
    await expect(
      withTenantTransaction(database, tenantId, async (transaction) => {
        await new UserRepository(transaction).create({
          tenantId,
          phone,
          phoneNormalized: phone,
        });
        throw new Error("force rollback");
      }),
    ).rejects.toThrow("force rollback");
    expect(
      await database("users").where({ tenant_id: tenantId }).first(),
    ).toBeUndefined();
  },
);

integrationTest("rejects missing or malformed tenant context", async () => {
  await expect(
    withTenantTransaction(database, "", async () => undefined),
  ).rejects.toThrow();
  await expect(
    withTenantTransaction(database, "not-a-uuid", async () => undefined),
  ).rejects.toThrow();
});

integrationTest(
  "runtime role cannot see tenant rows without tenant context",
  async () => {
    await database.transaction(async (transaction) => {
      await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
      const result = await transaction("users").count<{ count: string }[]>("*");
      expect(result).toEqual([{ count: "0" }]);
    });
  },
);

integrationTest(
  "deduplicates idempotency claims and rejects request drift",
  async () => {
    const tenantId = randomUUID();
    const input = {
      tenantId,
      key: randomUUID(),
      operation: "test.operation",
      requestHash: "a".repeat(64),
      expiresAt: new Date(Date.now() + 60_000),
    };
    await withTenantTransaction(database, tenantId, async (transaction) => {
      await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
      const repository = new IdempotencyRepository(transaction);
      expect((await repository.claim(input)).created).toBe(true);
      expect((await repository.claim(input)).created).toBe(false);
      await expect(
        repository.claim({ ...input, requestHash: "b".repeat(64) }),
      ).rejects.toThrow("IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST");
    });
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
  },
);

integrationTest(
  "persists hashed credentials and revokes a session family",
  async () => {
    const tenantId = randomUUID();
    const familyId = randomUUID();
    const user = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) => {
        await transaction.raw("SET LOCAL ROLE parc_auth_customer_runtime");
        const created = await new UserRepository(transaction).create({
          tenantId,
        });
        const credentials = new CredentialRepository(transaction);
        await credentials.create({
          tenantId,
          userId: created.id,
          type: "PASSWORD",
          hash: "argon2id-hash",
        });
        expect(
          (await credentials.findActive(created.id, "PASSWORD"))
            ?.credential_hash,
        ).toBe("argon2id-hash");
        const sessions = new SessionRepository(transaction);
        await sessions.create({
          tenantId,
          userId: created.id,
          sessionTokenHash: "session-hash",
          refreshTokenHash: "refresh-hash",
          tokenFamilyId: familyId,
          rotationSequence: 0,
          audience: "parc-mobile",
          subjectType: "CUSTOMER",
          authenticationMethods: ["PASSWORD"],
          expiresAt: new Date(Date.now() + 60_000),
          idleExpiresAt: new Date(Date.now() + 30_000),
        });
        expect(
          (
            await sessions.findActiveByRefreshTokenHash(
              tenantId,
              "refresh-hash",
            )
          )?.token_family_id,
        ).toBe(familyId);
        expect(await sessions.revokeFamily(familyId)).toBe(1);
        expect(
          await sessions.findActiveByRefreshTokenHash(tenantId, "refresh-hash"),
        ).toBeUndefined();
        return created;
      },
    );
    await database("user_sessions").where({ user_id: user.id }).delete();
    await database("user_credentials").where({ user_id: user.id }).delete();
    await database("users").where({ id: user.id }).delete();
  },
);

integrationTest(
  "deduplicates inbox receipts and commits an outbox record",
  async () => {
    const tenantId = randomUUID();
    const eventId = randomUUID();
    const aggregateId = randomUUID();
    await withTenantTransaction(database, tenantId, async (transaction) => {
      await transaction.raw("SET LOCAL ROLE parc_auth_customer_worker");
      const events = new EventRepository(transaction);
      const receipt = {
        tenantId,
        eventId,
        eventType: "tenant.activated.v1",
        sourceService: "parc-tenant-admin",
        payload: {},
      };
      expect(await events.receive(receipt)).toBe(true);
      expect(await events.receive(receipt)).toBe(false);
      await events.publish({
        tenantId,
        eventId: randomUUID(),
        eventType: "customer.registered.v1",
        aggregateType: "customer",
        aggregateId,
        payload: { customer_id: aggregateId },
      });
    });
    expect(
      await database("auth_customer_inbox_events")
        .where({ event_id: eventId })
        .count<{ count: string }[]>("*"),
    ).toEqual([{ count: "1" }]);
    expect(
      await database("auth_customer_outbox_events")
        .where({ aggregate_id: aggregateId })
        .count<{ count: string }[]>("*"),
    ).toEqual([{ count: "1" }]);
    await database("auth_customer_inbox_events")
      .where({ event_id: eventId })
      .delete();
    await database("auth_customer_outbox_events")
      .where({ aggregate_id: aggregateId })
      .delete();
  },
);
