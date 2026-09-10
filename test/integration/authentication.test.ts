import { randomUUID } from "node:crypto";
import argon2 from "argon2";
import knex, { type Knex } from "knex";
import { ApiError } from "../../src/http/api-error.js";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { CredentialRepository } from "../../src/repositories/credential-repository.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import {
  AuthenticationService,
  type AuthResultIssuer,
} from "../../src/services/authentication-service.js";

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

integrationTest(
  "authenticates passwords without identity enumeration",
  async () => {
    const tenantId = randomUUID();
    const phone = "+2348022222222";
    const user = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) => {
        const created = await new UserRepository(transaction).create({
          tenantId,
          phone,
          phoneNormalized: phone,
          status: "ACTIVE",
        });
        await new CredentialRepository(transaction).create({
          tenantId,
          userId: created.id,
          type: "PASSWORD",
          hash: await argon2.hash("correct horse battery staple"),
        });
        return created;
      },
    );
    const issuer: AuthResultIssuer = {
      issue: async ({ userId }) => ({
        access_token: `token-${userId}`,
        refresh_token: "refresh",
        token_type: "Bearer",
        expires_in: 300,
      }),
    };
    const authentication = new AuthenticationService(
      database,
      new MemoryRateLimiter(),
      issuer,
      "c".repeat(32),
    );
    const common = {
      tenantId,
      idempotencyKey: randomUUID(),
      deviceId: randomUUID(),
    };
    await expect(
      authentication.login({
        ...common,
        identifier: phone,
        password: "wrong-password",
      }),
    ).rejects.toMatchObject({
      status: 401,
      code: "AUTHENTICATION_FAILED",
      message: "Authentication failed",
    });
    expect(
      (await database("users").where({ id: user.id }).first())
        .failed_login_attempts,
    ).toBe(1);
    await expect(
      authentication.login({
        ...common,
        identifier: "+2348033333333",
        password: "wrong-password",
      }),
    ).rejects.toMatchObject({
      status: 401,
      code: "AUTHENTICATION_FAILED",
      message: "Authentication failed",
    });
    const result = await authentication.login({
      ...common,
      identifier: phone,
      password: "correct horse battery staple",
    });
    expect(result).toMatchObject({ access_token: `token-${user.id}` });
    const stored = await database("users").where({ id: user.id }).first();
    expect(stored.failed_login_attempts).toBe(0);
    await database("users").where({ id: user.id }).delete();
    await database("login_attempts").where({ tenant_id: tenantId }).delete();
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
  },
);

integrationTest(
  "creates, verifies, rotates, and rejects reused transaction PINs",
  async () => {
    const tenantId = randomUUID();
    const user = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) =>
        new UserRepository(transaction).create({
          tenantId,
          phone: "+2348044444444",
          phoneNormalized: "+2348044444444",
          status: "ACTIVE",
        }),
    );
    const authentication = new AuthenticationService(
      database,
      new MemoryRateLimiter(),
      { issue: async () => ({}) },
      "c".repeat(32),
    );
    const setupKey = randomUUID();
    const challenge = await authentication.startPinSetup(
      tenantId,
      user.id,
      setupKey,
    );
    await expect(
      authentication.startPinSetup(tenantId, user.id, setupKey),
    ).resolves.toEqual(challenge);
    const confirmKey = randomUUID();
    await authentication.confirmPin(
      tenantId,
      user.id,
      confirmKey,
      challenge.challenge_id,
      "1234",
    );
    await expect(
      authentication.confirmPin(
        tenantId,
        user.id,
        confirmKey,
        challenge.challenge_id,
        "1234",
      ),
    ).resolves.toBeUndefined();
    await expect(
      authentication.verifyPin(tenantId, user.id, randomUUID(), "1234"),
    ).resolves.toBeUndefined();
    await authentication.rotatePin(
      tenantId,
      user.id,
      randomUUID(),
      "1234",
      "5678",
    );
    await expect(
      authentication.verifyPin(tenantId, user.id, randomUUID(), "5678"),
    ).resolves.toBeUndefined();
    await expect(
      authentication.rotatePin(tenantId, user.id, randomUUID(), "5678", "1234"),
    ).rejects.toBeInstanceOf(ApiError);
    expect(
      await database("credential_history")
        .where({ user_id: user.id })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);
    await database("credential_history").where({ user_id: user.id }).delete();
    await database("users").where({ id: user.id }).delete();
  },
);

test("limits repeated attempts within the configured window", async () => {
  const limiter = new MemoryRateLimiter();
  expect(await limiter.consume("key", 2, 60)).toBe(true);
  expect(await limiter.consume("key", 2, 60)).toBe(true);
  expect(await limiter.consume("key", 2, 60)).toBe(false);
});
