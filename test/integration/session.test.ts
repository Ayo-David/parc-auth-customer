import { randomUUID } from "node:crypto";
import { decodeJwt, SignJWT } from "jose";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { CustomerRepository } from "../../src/repositories/customer-repository.js";
import { createJwtKeyRing } from "../../src/security/jwt-key-ring.js";
import { SessionService } from "../../src/services/session-service.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});
afterAll(async () => database.destroy());

async function fixture(): Promise<{
  tenantId: string;
  userId: string;
  customerId: string;
  sessions: SessionService;
  keys: Awaited<ReturnType<typeof createJwtKeyRing>>;
}> {
  const tenantId = randomUUID();
  const { user, customer } = await withTenantTransaction(
    database,
    tenantId,
    async (transaction) => {
      const user = await new UserRepository(transaction).create({
        tenantId,
        phone: "+2348088888888",
        phoneNormalized: "+2348088888888",
        status: "ACTIVE",
      });
      const customer = await new CustomerRepository(transaction).create({
        tenantId,
        userId: user.id,
        customerNumber: `CUS-${user.id.slice(0, 8)}`,
      });
      return { user, customer };
    },
  );
  const keys = await createJwtKeyRing({ activeKid: "test-key" });
  return {
    tenantId,
    userId: user.id,
    customerId: customer.id,
    keys,
    sessions: new SessionService(
      database,
      keys,
      "https://auth.parc.invalid",
      "t".repeat(32),
    ),
  };
}

async function cleanup(tenantId: string, userId: string): Promise<void> {
  await database("auth_customer_outbox_events")
    .where({ tenant_id: tenantId })
    .delete();
  await database("user_sessions").where({ tenant_id: tenantId }).delete();
  await database("user_devices").where({ tenant_id: tenantId }).delete();
  await database("customer_profiles").where({ user_id: userId }).delete();
  await database("users").where({ id: userId }).delete();
}

integrationTest(
  "accepts an older access token while its public key remains in the rotation set",
  async () => {
    const {
      tenantId,
      userId,
      customerId,
      sessions: oldIssuer,
      keys: oldKeys,
    } = await fixture();
    const pair = await oldIssuer.issue({
      tenantId,
      userId,
      authenticationMethods: ["PASSWORD"],
      idempotencyKey: randomUUID(),
    });
    const newKeys = await createJwtKeyRing({ activeKid: "new-key" });
    const oldPublicKey = oldKeys.publicKeys.get(oldKeys.activeKid);
    expect(oldPublicKey).toBeDefined();
    if (!oldPublicKey) throw new Error("Old public key missing");
    const verifier = new SessionService(
      database,
      {
        ...newKeys,
        publicKeys: new Map([
          ...newKeys.publicKeys,
          [oldKeys.activeKid, oldPublicKey],
        ]),
      },
      "https://auth.parc.invalid",
      "t".repeat(32),
    );
    await expect(verifier.verify(pair.access_token)).resolves.toMatchObject({
      subject: customerId,
    });
    await cleanup(tenantId, userId);
  },
);

integrationTest(
  "issues, verifies, introspects, refreshes, and logs out tokens",
  async () => {
    const { tenantId, userId, customerId, sessions, keys } = await fixture();
    const first = await sessions.issue({
      tenantId,
      userId,
      deviceId: randomUUID(),
      authenticationMethods: ["PASSWORD"],
      idempotencyKey: randomUUID(),
    });
    await expect(sessions.verify(first.access_token)).resolves.toMatchObject({
      subject: customerId,
      tenantId,
      audience: "mobile-bff",
    });
    await expect(
      sessions.introspect(first.access_token),
    ).resolves.toMatchObject({
      active: true,
      subject: customerId,
    });

    const claims = decodeJwt(first.access_token);
    const wrongAudience = await new SignJWT({
      tenant_id: claims.tenant_id,
      session_id: claims.session_id,
      subject_type: claims.subject_type,
      authentication_methods: claims.authentication_methods,
    })
      .setProtectedHeader({ alg: "RS256", kid: keys.activeKid })
      .setIssuer("https://auth.parc.invalid")
      .setAudience("admin-bff")
      .setSubject(userId)
      .setJti(String(claims.jti))
      .setIssuedAt()
      .setExpirationTime("15m")
      .sign(keys.privateKey);
    await expect(sessions.verify(wrongAudience)).rejects.toBeDefined();

    const rotated = await sessions.refresh(tenantId, first.refresh_token);
    await expect(sessions.verify(first.access_token)).rejects.toBeDefined();
    const rotatedIdentity = await sessions.verify(rotated.access_token);
    await sessions.logout(tenantId, rotatedIdentity.sessionId ?? "");
    await expect(sessions.verify(rotated.access_token)).rejects.toBeDefined();
    expect(
      await database("auth_customer_outbox_events")
        .where({ tenant_id: tenantId, event_type: "session.revoked.v1" })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);
    await cleanup(tenantId, userId);
  },
  15_000,
);

integrationTest(
  "detects concurrent refresh reuse and compromises the token family",
  async () => {
    const { tenantId, userId, sessions } = await fixture();
    const first = await sessions.issue({
      tenantId,
      userId,
      authenticationMethods: ["OTP"],
      idempotencyKey: randomUUID(),
    });
    const results = await Promise.allSettled([
      sessions.refresh(tenantId, first.refresh_token),
      sessions.refresh(tenantId, first.refresh_token),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    const successful = results.find(
      (
        result,
      ): result is PromiseFulfilledResult<
        Awaited<ReturnType<SessionService["refresh"]>>
      > => result.status === "fulfilled",
    );
    expect(successful).toBeDefined();
    await expect(
      sessions.verify(successful?.value.access_token ?? ""),
    ).rejects.toBeDefined();
    const family = await database("user_sessions").where({
      tenant_id: tenantId,
    });
    expect(family.every(({ compromised_at }) => compromised_at !== null)).toBe(
      true,
    );
    expect(
      await database("auth_customer_outbox_events")
        .where({ tenant_id: tenantId, event_type: "session.revoked.v1" })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);
    await cleanup(tenantId, userId);
  },
  15_000,
);
