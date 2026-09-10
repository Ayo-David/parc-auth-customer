import { randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { MemoryOtpSecretStore } from "../../src/security/otp-secret-store.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import type { AuthResultIssuer } from "../../src/services/authentication-service.js";
import { CustomerMfaService } from "../../src/services/customer-mfa-service.js";
import type { AdministratorTenantAdminClient } from "../../src/services/tenant-admin-client.js";

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
  "applies tenant customer-MFA policy and consumes its challenge once",
  async () => {
    const tenantId = randomUUID();
    const user = await withTenantTransaction(
      database,
      tenantId,
      (transaction) =>
        new UserRepository(transaction).create({
          tenantId,
          phone: "+2348011111111",
          phoneNormalized: "+2348011111111",
          status: "ACTIVE",
        }),
    );
    let required = true;
    const tenantAdmin: AdministratorTenantAdminClient = {
      verifyAdministrator: async () => {
        throw new Error("unused");
      },
      getAdministratorAuthorization: async () => {
        throw new Error("unused");
      },
      getTenantAuthenticationPolicy: async () => ({
        customer_mfa_required: required,
        allowed_customer_mfa_methods: ["SMS_OTP"],
        passkey: null,
        version: 3,
      }),
      getPlatformAuthenticationPolicy: async () => ({
        customer_mfa_required: false,
        allowed_customer_mfa_methods: [],
        passkey: null,
        version: 1,
      }),
      consumeApproval: async () => {
        throw new Error("unused");
      },
    };
    const issuer: AuthResultIssuer = {
      issue: async (input) => ({
        subject: input.userId,
        methods: input.authenticationMethods,
      }),
    };
    const secrets = new MemoryOtpSecretStore();
    const service = new CustomerMfaService(
      database,
      tenantAdmin,
      secrets,
      new MemoryRateLimiter(),
      issuer,
      "c".repeat(32),
    );
    const pending = await service.challenge({
      tenantId,
      userId: user.id,
      deviceId: randomUUID(),
    });
    expect(pending?.mfa_required).toBe(true);
    const challengeId = (pending?.challenge as { challenge_id: string })
      .challenge_id;
    const stored = await secrets.take(challengeId);
    if (!stored) throw new Error("Customer MFA state missing");
    const { code } = JSON.parse(stored) as { code: string };
    await expect(
      service.verify({
        tenantId,
        challengeId,
        response: code,
        idempotencyKey: randomUUID(),
      }),
    ).resolves.toMatchObject({
      subject: user.id,
      methods: ["PASSWORD", "SMS_OTP", "MFA"],
    });
    await expect(
      service.verify({
        tenantId,
        challengeId,
        response: code,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    required = false;
    await expect(
      service.challenge({ tenantId, userId: user.id, deviceId: randomUUID() }),
    ).resolves.toBeUndefined();

    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
    await database("authentication_challenges")
      .where({ tenant_id: tenantId })
      .delete();
    await database("users").where({ id: user.id }).delete();
  },
);
