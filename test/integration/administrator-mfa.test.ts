import { randomUUID } from "node:crypto";
import { decodeJwt } from "jose";
import knex, { type Knex } from "knex";
import { MemoryOtpSecretStore } from "../../src/security/otp-secret-store.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import { createJwtKeyRing } from "../../src/security/jwt-key-ring.js";
import { AdministratorAuthenticationService } from "../../src/services/administrator-authentication-service.js";
import { SessionService } from "../../src/services/session-service.js";
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
  "requires MFA, issues a short administrator session, rejects replay and stale authorization",
  async () => {
    const tenantId = randomUUID();
    const administratorId = randomUUID();
    let authorizationVersion = 7;
    let mfaRequired = true;
    let approvalConsumed = false;
    const tenantAdmin: AdministratorTenantAdminClient = {
      verifyAdministrator: async () => ({
        administrator_id: administratorId,
        tenant_id: tenantId,
        scope: "TENANT",
        status: "ACTIVE",
        roles: ["TENANT_ADMIN"],
        authorization_version: authorizationVersion,
        mfa_required: mfaRequired,
        allowed_mfa_methods: ["SMS_OTP"],
      }),
      getAdministratorAuthorization: async () => ({
        roles: ["TENANT_ADMIN"],
        permissions: ["customers:read"],
        authorization_version: authorizationVersion,
      }),
      getTenantAuthenticationPolicy: async () => ({
        customer_mfa_required: false,
        allowed_customer_mfa_methods: [],
        passkey: null,
        version: 1,
      }),
      getPlatformAuthenticationPolicy: async () => ({
        customer_mfa_required: false,
        allowed_customer_mfa_methods: [],
        passkey: null,
        version: 1,
      }),
      consumeApproval: async () => {
        approvalConsumed = true;
      },
    };
    const secrets = new MemoryOtpSecretStore();
    const sessions = new SessionService(
      database,
      await createJwtKeyRing({ activeKid: "admin-test-key" }),
      "https://auth.parc.invalid",
      "t".repeat(32),
      tenantAdmin,
    );
    const service = new AdministratorAuthenticationService(
      database,
      tenantAdmin,
      sessions,
      secrets,
      new MemoryRateLimiter(),
      "c".repeat(32),
    );

    const enrollment = (await service.enroll({
      administratorId,
      tenantId,
      scope: "TENANT",
      method: "SMS_OTP",
      identifier: "+2348000000000",
    })) as { challenge_id: string };
    const enrollmentCode = await secrets.take(enrollment.challenge_id);
    if (!enrollmentCode) throw new Error("Enrollment code missing");
    await expect(
      service.verify({
        tenantId,
        scope: "TENANT",
        challengeId: enrollment.challenge_id,
        response: enrollmentCode,
      }),
    ).resolves.toEqual({ enrolled: true });

    const pending = await service.authenticate({
      identifier: "admin@example.test",
      password: "not-retained-here",
      tenantContext: tenantId,
      idempotencyKey: randomUUID(),
    });
    const challengeId = (pending.challenge as { challenge_id: string })
      .challenge_id;
    const code = await secrets.take(challengeId);
    if (!code) throw new Error("Login MFA code missing");
    const pair = await service.verify({
      tenantId,
      scope: "TENANT",
      challengeId,
      response: code,
    });
    expect("access_token" in pair).toBe(true);
    if (!("access_token" in pair)) throw new Error("Token pair expected");
    const claims = decodeJwt(pair.access_token);
    expect(claims).toMatchObject({
      sub: administratorId,
      tenant_id: tenantId,
      subject_type: "ADMINISTRATOR",
      scope: "TENANT",
      authorization_version: 7,
      aud: "admin-bff",
    });
    expect((claims.exp ?? 0) - (claims.iat ?? 0)).toBe(300);
    await expect(
      service.verify({
        tenantId,
        scope: "TENANT",
        challengeId,
        response: code,
      }),
    ).rejects.toMatchObject({ code: "AUTHENTICATION_FAILED" });

    authorizationVersion = 8;
    await expect(
      sessions.introspect(pair.access_token, "admin-bff"),
    ).resolves.toEqual({ active: false });

    mfaRequired = false;
    await expect(
      service.authenticate({
        identifier: "admin@example.test",
        password: "not-retained-here",
        tenantContext: tenantId,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "MFA_POLICY_INVALID" });

    await service.reset({
      administratorId,
      tenantId,
      scope: "TENANT",
      method: "SMS_OTP",
      approvalId: randomUUID(),
      reason: "Administrator replaced their device",
      idempotencyKey: randomUUID(),
    });
    expect(approvalConsumed).toBe(true);

    await database("authentication_challenges")
      .where({ tenant_id: tenantId })
      .delete();
    await database("user_sessions").where({ tenant_id: tenantId }).delete();
    await database("user_2fa_methods").where({ tenant_id: tenantId }).delete();
  },
);

integrationTest(
  "stores a platform administrator without tenant/customer ownership",
  async () => {
    const administratorId = randomUUID();
    const tenantAdmin: AdministratorTenantAdminClient = {
      verifyAdministrator: async () => {
        throw new Error("unused");
      },
      getAdministratorAuthorization: async () => ({
        roles: [],
        permissions: [],
        authorization_version: 1,
      }),
      getTenantAuthenticationPolicy: async () => ({
        customer_mfa_required: false,
        allowed_customer_mfa_methods: [],
        passkey: null,
        version: 1,
      }),
      getPlatformAuthenticationPolicy: async () => ({
        customer_mfa_required: false,
        allowed_customer_mfa_methods: [],
        passkey: null,
        version: 1,
      }),
      consumeApproval: async () => undefined,
    };
    const sessions = new SessionService(
      database,
      await createJwtKeyRing({ activeKid: "platform-test-key" }),
      "https://auth.parc.invalid",
      "t".repeat(32),
      tenantAdmin,
    );
    const pair = await sessions.issueAdministrator({
      tenantId: null,
      administratorId,
      scope: "PLATFORM",
      authorizationVersion: 1,
      authenticationMethods: ["PASSWORD", "SMS_OTP", "MFA"],
    });
    expect(decodeJwt(pair.access_token)).toMatchObject({
      sub: administratorId,
      tenant_id: null,
      scope: "PLATFORM",
    });
    const row = await database("user_sessions")
      .where({ subject_id: administratorId })
      .first();
    expect(row).toMatchObject({
      tenant_id: null,
      user_id: null,
      scope_type: "PLATFORM",
    });
    await database("user_sessions")
      .where({ subject_id: administratorId })
      .delete();
  },
);
