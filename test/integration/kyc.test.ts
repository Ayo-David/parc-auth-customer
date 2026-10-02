import { createHmac, randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import type {
  KycProvider,
  KycProviderResult,
} from "../../src/providers/kyc-provider.js";
import { StaticKycProviderResolver } from "../../src/providers/kyc-provider.js";
import { KycService } from "../../src/services/kyc-service.js";
import { withTenantTransaction } from "../../src/database/transaction.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

const hashSecret = "h".repeat(32);
const signingSecret = "s".repeat(32);
const evidenceKeys = {
  identifierHashSecret: hashSecret,
  identifierHashKeyId: "hash-v1",
  resultSigningSecret: signingSecret,
  resultSigningKeyId: "sign-v1",
};

class FakeKycProvider implements KycProvider {
  public readonly name = "VERIFYME" as const;
  public calls = 0;
  public lastIdentityValue?: string;

  public constructor(private readonly result: KycProviderResult) {}

  public verifyIdentity(input: {
    verificationId: string;
    identityType: "NIN" | "BVN";
    identityValue: string;
    firstName?: string;
    lastName?: string;
  }): Promise<KycProviderResult> {
    this.calls += 1;
    this.lastIdentityValue = input.identityValue;
    return Promise.resolve(this.result);
  }

  public verifyBiometric(input: {
    verificationId: string;
    identityType: "NIN" | "BVN";
    identityValue: string;
    livenessReference: string;
  }): Promise<KycProviderResult> {
    this.calls += 1;
    this.lastIdentityValue = input.identityValue;
    return Promise.resolve(this.result);
  }
}

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
  userId: string;
  customerId: string;
  consentId: string;
}> {
  return withTenantTransaction(database, tenantId, async (transaction) => {
    const [user] = await transaction("users")
      .insert({
        tenant_id: tenantId,
        user_type: "CUSTOMER",
        status: "ACTIVE",
        phone: `+23480${Math.floor(Math.random() * 1_000_000_000)
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
        consent_document_id: randomUUID(),
        consent_type: "KYC",
        document_version: "2026-09-10",
        granted: true,
        granted_at: new Date(),
        purpose: "Identity verification",
      })
      .returning("id");
    return {
      userId: user.id,
      customerId: customer.id,
      consentId: consent.id,
    };
  });
}

async function cleanTenant(tenantId: string): Promise<void> {
  await database("identity_verification_evidence")
    .where({ tenant_id: tenantId })
    .delete();
  await database("kyc_verification_results")
    .where({ tenant_id: tenantId })
    .delete();
  await database("kyc_profiles").where({ tenant_id: tenantId }).delete();
  await database("kyc_verifications").where({ tenant_id: tenantId }).delete();
  await database("auth_customer_outbox_events")
    .where({ tenant_id: tenantId })
    .delete();
  await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
  await database("users").where({ tenant_id: tenantId }).delete();
}

integrationTest(
  "verifies identity without retaining plaintext BVN and replays idempotently",
  async () => {
    const tenantId = randomUUID();
    const customer = await createCustomerWithConsent(tenantId);
    const provider = new FakeKycProvider({
      outcome: "VERIFIED",
      providerReference: "vm-safe-reference",
      providerConfigurationVersion: "verifyme-v1",
      resultCode: "SUCCESS",
      safeResult: { status: "success", field_matches: { firstname: true } },
    });
    const service = new KycService(
      database,
      new StaticKycProviderResolver(provider),
      "i".repeat(32),
      evidenceKeys,
    );
    const identityValue = "10000000001";
    const input = {
      tenantId,
      userId: customer.userId,
      identityType: "BVN" as const,
      identityValue,
      consentId: customer.consentId,
      idempotencyKey: randomUUID(),
      correlationId: randomUUID(),
    };

    const first = await service.start(input);
    const replay = await service.start(input);
    expect(replay).toEqual(first);
    expect(first).toMatchObject({
      identity_type: "BVN",
      masked_identity: "*******0001",
      provider: "VERIFYME",
      status: "VERIFIED",
    });
    expect(provider.calls).toBe(1);
    expect(provider.lastIdentityValue).toBe(identityValue);

    const evidence = await database("identity_verification_evidence")
      .where({ tenant_id: tenantId })
      .first();
    expect(evidence.identifier_masked).toBe("*******0001");
    expect(evidence.identifier_hash).toBe(
      createHmac("sha256", hashSecret)
        .update(`${tenantId}:BVN:${identityValue}`)
        .digest("hex"),
    );
    expect(evidence.identifier_hash).not.toContain(identityValue);
    expect(evidence.hash_key_id).toBe("hash-v1");
    expect(evidence.signing_key_id).toBe("sign-v1");
    expect(evidence.result_signature).toBe(
      createHmac("sha256", signingSecret)
        .update(evidence.result_digest)
        .digest("hex"),
    );
    const serializedRows = JSON.stringify(
      await database("kyc_verifications")
        .where({ tenant_id: tenantId })
        .select("*"),
    );
    expect(serializedRows).not.toContain(identityValue);
    expect(
      JSON.stringify(
        await database("kyc_verification_results")
          .where({ tenant_id: tenantId })
          .select("*"),
      ),
    ).not.toContain(identityValue);

    await cleanTenant(tenantId);
  },
  15_000,
);

integrationTest(
  "requires active customer-owned KYC consent before calling the provider",
  async () => {
    const tenantId = randomUUID();
    const customer = await createCustomerWithConsent(tenantId);
    const provider = new FakeKycProvider({
      outcome: "VERIFIED",
      providerReference: "unused",
      providerConfigurationVersion: "verifyme-v1",
      resultCode: "SUCCESS",
      safeResult: {},
    });
    const service = new KycService(
      database,
      new StaticKycProviderResolver(provider),
      "i".repeat(32),
      evidenceKeys,
    );
    await expect(
      service.start({
        tenantId,
        userId: customer.userId,
        identityType: "NIN",
        identityValue: "10000000001",
        consentId: randomUUID(),
        idempotencyKey: randomUUID(),
        correlationId: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "KYC_CONSENT_REQUIRED", status: 422 });
    expect(provider.calls).toBe(0);
    await cleanTenant(tenantId);
  },
  15_000,
);

integrationTest(
  "keeps ambiguous provider outcomes pending and isolates verification reads",
  async () => {
    const tenantId = randomUUID();
    const otherTenantId = randomUUID();
    const customer = await createCustomerWithConsent(tenantId);
    const provider = new FakeKycProvider({
      outcome: "PENDING",
      providerReference: "verifyme-request:ambiguous",
      providerConfigurationVersion: "verifyme-v1",
      resultCode: "PROVIDER_OUTCOME_UNKNOWN",
      safeResult: { status: "pending" },
    });
    const service = new KycService(
      database,
      new StaticKycProviderResolver(provider),
      "i".repeat(32),
      evidenceKeys,
    );
    const result = await service.start({
      tenantId,
      userId: customer.userId,
      identityType: "NIN",
      identityValue: "10000000001",
      consentId: customer.consentId,
      idempotencyKey: randomUUID(),
      correlationId: randomUUID(),
    });
    expect(result.status).toBe("PENDING");
    expect(
      await database("identity_verification_evidence")
        .where({ tenant_id: tenantId })
        .count("* as count"),
    ).toEqual([{ count: "0" }]);
    await expect(
      service.get(otherTenantId, customer.userId, result.id),
    ).rejects.toMatchObject({
      code: "KYC_VERIFICATION_NOT_FOUND",
      status: 404,
    });
    await cleanTenant(tenantId);
  },
  15_000,
);
