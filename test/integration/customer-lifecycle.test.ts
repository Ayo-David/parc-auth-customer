import { randomUUID } from "node:crypto";
import knex, { type Knex } from "knex";
import pino from "pino";
import request from "supertest";
import { createApp } from "../../src/app.js";
import { loadConfig } from "../../src/config/env.js";
import type { AccessTokenVerifier } from "../../src/security/access-token-verifier.js";
import { CustomerService } from "../../src/services/customer-service.js";
import type {
  ConsentDocument,
  TenantAdminClient,
} from "../../src/services/tenant-admin-client.js";

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
  "registers a progressive customer atomically and replays idempotently",
  async () => {
    const tenantId = randomUUID();
    const consentId = randomUUID();
    const documents: ConsentDocument[] = [
      {
        id: consentId,
        tenant_id: tenantId,
        consent_type: "TERMS_AND_CONDITIONS",
        document_version: "2026-09-09",
      },
    ];
    const tenantAdmin: TenantAdminClient = {
      validateRegistration: async () => documents,
    };
    const service = new CustomerService(database, tenantAdmin, "s".repeat(32));
    const idempotencyKey = randomUUID();
    const registration = {
      tenantId,
      idempotencyKey,
      correlationId: randomUUID(),
      phoneNumber: "+2348012345678",
      password: "correct horse battery staple",
      consentIds: [consentId],
    };

    const first = await service.register(registration);
    const replay = await service.register(registration);
    expect(replay).toEqual(first);
    expect(first.first_name).toBeUndefined();
    expect(first.last_name).toBeUndefined();

    const user = await database("users").where({ tenant_id: tenantId }).first();
    const profile = await database("customer_profiles")
      .where({ tenant_id: tenantId })
      .first();
    const credential = await database("user_credentials")
      .where({ tenant_id: tenantId })
      .first();
    const consent = await database("user_consents")
      .where({ tenant_id: tenantId })
      .first();
    expect(profile.first_name).toBeNull();
    expect(profile.last_name).toBeNull();
    expect(credential.credential_hash).not.toContain(registration.password);
    expect(credential.credential_hash).toMatch(/^\$argon2id\$/);
    expect(consent.consent_document_id).toBe(consentId);
    expect(
      await database("auth_customer_outbox_events")
        .where({ tenant_id: tenantId })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);

    const updated = await service.update(tenantId, user.id, randomUUID(), {
      firstName: "Ada",
      lastName: "Okafor",
      email: "ADA@EXAMPLE.COM",
    });
    expect(updated.first_name).toBe("Ada");
    expect(updated.last_name).toBe("Okafor");
    expect(updated.masked_email).toBe("a***@example.com");

    await database("users").where({ tenant_id: tenantId }).delete();
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
  },
  15_000,
);

integrationTest(
  "serializes concurrent duplicate registration safely",
  async () => {
    const tenantId = randomUUID();
    const consentId = randomUUID();
    const tenantAdmin: TenantAdminClient = {
      validateRegistration: async () => [
        {
          id: consentId,
          tenant_id: tenantId,
          consent_type: "PRIVACY_POLICY",
          document_version: "2026-09-09",
        },
      ],
    };
    const service = new CustomerService(database, tenantAdmin, "s".repeat(32));
    const registration = {
      tenantId,
      idempotencyKey: randomUUID(),
      correlationId: randomUUID(),
      phoneNumber: "+2348098765432",
      password: "another correct horse battery staple",
      consentIds: [consentId],
    };
    const [first, second] = await Promise.all([
      service.register(registration),
      service.register(registration),
    ]);
    expect(second).toEqual(first);
    expect(
      await database("users")
        .where({ tenant_id: tenantId })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);
    expect(
      await database("auth_customer_outbox_events")
        .where({ tenant_id: tenantId })
        .count("* as count"),
    ).toEqual([{ count: "1" }]);

    await database("users").where({ tenant_id: tenantId }).delete();
    await database("idempotency_keys").where({ tenant_id: tenantId }).delete();
    await database("auth_customer_outbox_events")
      .where({ tenant_id: tenantId })
      .delete();
  },
  15_000,
);

integrationTest(
  "enforces authenticated tenant context on profile routes",
  async () => {
    const tenantId = randomUUID();
    const otherTenantId = randomUUID();
    const tenantAdmin: TenantAdminClient = {
      validateRegistration: async () => [],
    };
    const verifier: AccessTokenVerifier = {
      verify: async () => ({
        subject: randomUUID(),
        tenantId,
        audience: "mobile-bff",
      }),
    };
    const config = loadConfig({
      NODE_ENV: "test",
      LOG_LEVEL: "silent",
      DATABASE_URL: databaseUrl,
    });
    const app = createApp({
      config,
      logger: pino({ level: "silent" }),
      customerService: new CustomerService(
        database,
        tenantAdmin,
        "s".repeat(32),
      ),
      accessTokenVerifier: verifier,
    });
    const response = await request(app)
      .get("/v1/customers/me")
      .set("authorization", "Bearer signed-token")
      .set("x-tenant-id", otherTenantId);
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("TENANT_MISMATCH");
  },
);
