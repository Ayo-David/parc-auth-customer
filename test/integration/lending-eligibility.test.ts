import { randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { LendingEligibilityService } from "../../src/services/lending-eligibility-service.js";

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

async function createCustomerWithConsent(tenantId: string): Promise<{
  customerId: string;
  consentId: string;
  consentDocumentId: string;
  userId: string;
}> {
  const consentDocumentId = randomUUID();
  return withTenantTransaction(database, tenantId, async (transaction) => {
    const [user] = await transaction("users")
      .insert({
        tenant_id: tenantId,
        user_type: "CUSTOMER",
        status: "ACTIVE",
        phone: `+23481${Math.floor(Math.random() * 1_000_000_000)
          .toString()
          .padStart(9, "0")}`,
      })
      .returning("id");
    const [customer] = await transaction("customer_profiles")
      .insert({
        tenant_id: tenantId,
        user_id: user.id,
        customer_number: `CUS-${randomUUID().replaceAll("-", "")}`,
      })
      .returning("id");
    const [consent] = await transaction("user_consents")
      .insert({
        tenant_id: tenantId,
        user_id: user.id,
        consent_document_id: consentDocumentId,
        consent_type: "TERMS_AND_CONDITIONS",
        document_version: "1.0",
        granted: true,
        granted_at: new Date(),
        evidence_digest: "a".repeat(64),
      })
      .returning("id");
    return {
      customerId: customer.id,
      consentId: consent.id,
      consentDocumentId,
      userId: user.id,
    };
  });
}

async function cleanTenant(tenantId: string): Promise<void> {
  await database("user_consents").where({ tenant_id: tenantId }).delete();
  await database("customer_profiles").where({ tenant_id: tenantId }).delete();
  await database("users").where({ tenant_id: tenantId }).delete();
}

async function consentOf(
  tenantId: string,
  customerId: string,
  consentReference: string,
): Promise<{ valid: boolean; reference: string; document_version: unknown }> {
  const result = await new LendingEligibilityService(database).get({
    tenantId,
    customerId,
    consentReference,
  });
  return result.consent as {
    valid: boolean;
    reference: string;
    document_version: unknown;
  };
}

integrationTest(
  "accepts the granted consent id or the consent document it accepted",
  async () => {
    const tenantId = randomUUID();
    try {
      const customer = await createCustomerWithConsent(tenantId);
      await expect(
        consentOf(tenantId, customer.customerId, customer.consentId),
      ).resolves.toMatchObject({ valid: true, document_version: "1.0" });
      await expect(
        consentOf(tenantId, customer.customerId, customer.consentDocumentId),
      ).resolves.toMatchObject({
        valid: true,
        reference: customer.consentDocumentId,
        document_version: "1.0",
      });
      await expect(
        consentOf(tenantId, customer.customerId, randomUUID()),
      ).resolves.toMatchObject({ valid: false });
    } finally {
      await cleanTenant(tenantId);
    }
  },
);

integrationTest("rejects a withdrawn consent", async () => {
  const tenantId = randomUUID();
  try {
    const customer = await createCustomerWithConsent(tenantId);
    await withTenantTransaction(database, tenantId, (transaction) =>
      transaction("user_consents")
        .where({ id: customer.consentId })
        .update({ withdrawn_at: new Date() }),
    );
    await expect(
      consentOf(tenantId, customer.customerId, customer.consentDocumentId),
    ).resolves.toMatchObject({ valid: false });
  } finally {
    await cleanTenant(tenantId);
  }
});

integrationTest(
  "never accepts another customer's or another tenant's consent",
  async () => {
    const tenantId = randomUUID();
    const otherTenantId = randomUUID();
    try {
      const customer = await createCustomerWithConsent(tenantId);
      const sameTenant = await createCustomerWithConsent(tenantId);
      const otherTenant = await createCustomerWithConsent(otherTenantId);
      for (const reference of [
        sameTenant.consentId,
        sameTenant.consentDocumentId,
        otherTenant.consentId,
        otherTenant.consentDocumentId,
      ])
        await expect(
          consentOf(tenantId, customer.customerId, reference),
        ).resolves.toMatchObject({ valid: false });
    } finally {
      await cleanTenant(tenantId);
      await cleanTenant(otherTenantId);
    }
  },
);
