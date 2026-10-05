import { randomUUID } from "node:crypto";
import argon2 from "argon2";
import knex, { type Knex } from "knex";
import { OnboardingService } from "../../src/services/onboarding-service.js";
import type { TenantAdminClient } from "../../src/services/tenant-admin-client.js";

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
  "persists ordered progressive onboarding and a distinct login passcode",
  async () => {
    const tenantId = randomUUID();
    const consentId = randomUUID();
    const tenantAdmin: TenantAdminClient = {
      validateRegistration: async () => [
        {
          id: consentId,
          tenant_id: tenantId,
          consent_type: "TERMS_AND_CONDITIONS",
          document_version: "2026-09-14",
        },
      ],
    };
    const service = new OnboardingService(
      database,
      tenantAdmin,
      "o".repeat(32),
    );
    const registration = await service.start({
      tenantId,
      idempotencyKey: randomUUID(),
      phoneNumber: "+2348023456789",
      consentIds: [consentId],
    });
    expect(registration.current_step).toBe("PHONE_VERIFICATION");
    const session = await database("customer_onboarding_sessions")
      .where({ id: registration.onboarding_id })
      .first();
    await database("users")
      .where({ id: session.user_id })
      .update({ phone_verified: true });
    await service.markPhoneVerifiedBySession(
      tenantId,
      registration.onboarding_id,
    );
    await service.updateEmail(tenantId, session.user_id);
    await database("customer_onboarding_sessions")
      .where({ id: registration.onboarding_id })
      .update({
        current_step: "INCOME",
        completed_steps: JSON.stringify([
          "PHONE_VERIFICATION",
          "EMAIL",
          "IDENTITY",
          "FACE_VERIFICATION",
          "ADDRESS",
          "COMPLIANCE",
        ]),
      });
    await service.updateIncome(tenantId, session.user_id, {
      occupation: "Engineer",
      annualIncomeBand: "NGN_5M_10M",
      hasOtherIncome: false,
    });
    await service.setLoginPasscode(tenantId, session.user_id, "123456");
    const credential = await database("user_credentials")
      .where({ user_id: session.user_id, credential_type: "LOGIN_PASSCODE" })
      .first();
    expect(credential.credential_hash).not.toContain("123456");
    expect(await argon2.verify(credential.credential_hash, "123456")).toBe(
      true,
    );
    const completed = (await service.completeBiometric(
      tenantId,
      session.user_id,
      false,
    )) as { status: string };
    expect(completed.status).toBe("COMPLETED");
    await database("users").where({ id: session.user_id }).delete();
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
  },
  15_000,
);
