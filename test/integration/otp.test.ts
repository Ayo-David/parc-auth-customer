import { randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { MemoryOtpSecretStore } from "../../src/security/otp-secret-store.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import type { AuthResultIssuer } from "../../src/services/authentication-service.js";
import { OtpService } from "../../src/services/otp-service.js";

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
  "verifies OTP once and never places its value in an event",
  async () => {
    const tenantId = randomUUID();
    const phone = "+2348055555555";
    const user = await withTenantTransaction(
      database,
      tenantId,
      (transaction) =>
        new UserRepository(transaction).create({
          tenantId,
          phone,
          phoneNormalized: phone,
        }),
    );
    const secrets = new MemoryOtpSecretStore();
    const issuer: AuthResultIssuer = {
      issue: async ({ userId }) => ({
        access_token: `otp-${userId}`,
        refresh_token: "refresh",
        token_type: "Bearer",
        expires_in: 300,
      }),
    };
    const otp = new OtpService(
      database,
      new MemoryRateLimiter(),
      secrets,
      issuer,
      "o".repeat(32),
    );
    const requestInput = {
      tenantId,
      idempotencyKey: randomUUID(),
      purpose: "PHONE_VERIFICATION" as const,
      channel: "SMS" as const,
      destination: phone,
    };
    const challenge = await otp.request(requestInput);
    await expect(otp.request(requestInput)).resolves.toEqual(challenge);
    const code = await secrets.take(challenge.challenge_id);
    expect(code).toMatch(/^[0-9]{6}$/);
    const event = await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId, event_type: "notification.requested.v1" })
      .first();
    expect(JSON.stringify(event.payload)).not.toContain(code);
    await expect(
      otp.verify({
        tenantId: randomUUID(),
        idempotencyKey: randomUUID(),
        challengeId: challenge.challenge_id,
        code: code ?? "",
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    const concurrentVerification = await Promise.allSettled([
      otp.verify({
        tenantId,
        idempotencyKey: randomUUID(),
        challengeId: challenge.challenge_id,
        code: code ?? "",
      }),
      otp.verify({
        tenantId,
        idempotencyKey: randomUUID(),
        challengeId: challenge.challenge_id,
        code: code ?? "",
      }),
    ]);
    expect(
      concurrentVerification.filter(({ status }) => status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      concurrentVerification.filter(({ status }) => status === "rejected"),
    ).toHaveLength(1);
    expect(
      (await database("users").where({ id: user.id }).first()).phone_verified,
    ).toBe(true);
    await expect(
      otp.verify({
        tenantId,
        idempotencyKey: randomUUID(),
        challengeId: challenge.challenge_id,
        code: code ?? "",
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
    await database("users").where({ id: user.id }).delete();
  },
  15_000,
);

integrationTest("does not enumerate an unknown OTP destination", async () => {
  const tenantId = randomUUID();
  const otp = new OtpService(
    database,
    new MemoryRateLimiter(),
    new MemoryOtpSecretStore(),
    { issue: async () => ({}) },
    "o".repeat(32),
  );
  const challenge = await otp.request({
    tenantId,
    idempotencyKey: randomUUID(),
    purpose: "LOGIN",
    channel: "SMS",
    destination: "+2348066666666",
  });
  expect(challenge.challenge_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .count("* as count"),
  ).toEqual([{ count: "0" }]);
  await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
  await database("authentication_challenges")
    .where({ tenant_id: tenantId })
    .delete();
});

integrationTest(
  "rejects expired OTPs and persists failed attempts",
  async () => {
    const tenantId = randomUUID();
    const phone = "+2348077777777";
    const user = await withTenantTransaction(
      database,
      tenantId,
      (transaction) =>
        new UserRepository(transaction).create({
          tenantId,
          phone,
          phoneNormalized: phone,
        }),
    );
    const secrets = new MemoryOtpSecretStore();
    const otp = new OtpService(
      database,
      new MemoryRateLimiter(),
      secrets,
      { issue: async () => ({}) },
      "o".repeat(32),
    );
    const challenge = await otp.request({
      tenantId,
      idempotencyKey: randomUUID(),
      purpose: "LOGIN",
      channel: "SMS",
      destination: phone,
    });
    const code = await secrets.take(challenge.challenge_id);
    await database("authentication_challenges")
      .where({ id: challenge.challenge_id })
      .update({ expires_at: new Date(Date.now() - 1_000) });
    await expect(
      otp.verify({
        tenantId,
        idempotencyKey: randomUUID(),
        challengeId: challenge.challenge_id,
        code: code ?? "",
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });
    expect(
      (
        await database("authentication_challenges")
          .where({ id: challenge.challenge_id })
          .first()
      ).attempts,
    ).toBe(1);
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
    await database("users").where({ id: user.id }).delete();
  },
);
