import { randomUUID } from "node:crypto";
import { exportSPKI, generateKeyPair, SignJWT } from "jose";
import pino from "pino";
import request from "supertest";
import { createApp } from "../../src/app.js";
import { loadConfig } from "../../src/config/env.js";
import { ClientAssertionVerifier } from "../../src/security/client-assertion-verifier.js";
import { createJwtKeyRing } from "../../src/security/jwt-key-ring.js";
import { createParcAuth } from "../../src/security/parc-service-auth.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";
import { scopeCatalogue } from "../../src/security/scope-catalogue.js";
import { ServiceTokenService } from "../../src/services/service-token-service.js";
import type { LendingEligibilityService } from "../../src/services/lending-eligibility-service.js";

const config = loadConfig({ NODE_ENV: "test", LOG_LEVEL: "silent" });
type Key = Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
const tenantId = "11111111-1111-4111-8111-111111111111";
const customerId = "22222222-2222-4222-8222-222222222222";
const consentReference = "33333333-3333-4333-8333-333333333333";

async function harness() {
  const keys = await createJwtKeyRing({ activeKid: "test" });
  const clientKeys = {
    lending: await generateKeyPair("ES256", { extractable: true }),
    mobile: await generateKeyPair("ES256", { extractable: true }),
  };
  const spki = async (key: Key) =>
    Buffer.from(await exportSPKI(key)).toString("base64");
  const tokens = new ServiceTokenService({
    keys,
    issuer: config.JWT_ISSUER,
    catalogue: scopeCatalogue,
    tenants: { getTenantStatus: () => Promise.resolve("ACTIVE") },
    administrators: {
      getAdministratorAuthorization: () =>
        Promise.resolve({
          roles: [],
          permissions: [],
          authorization_version: 1,
        }),
    },
    sessions: {
      introspect: () => Promise.resolve({ active: false }),
      sessionActive: () => Promise.resolve(true),
    },
  });
  const app = createApp({
    config,
    logger: pino({ level: "silent" }),
    lendingEligibilityService: {
      get: () => Promise.resolve({ eligible: true }),
    } as unknown as LendingEligibilityService,
    serviceTokens: {
      tokens,
      clients: await ClientAssertionVerifier.create({
        clientKeysJson: JSON.stringify({
          "parc-lending": { l1: await spki(clientKeys.lending.publicKey) },
          "parc-mobile-bff": { m1: await spki(clientKeys.mobile.publicKey) },
        }),
        audience: config.JWT_ISSUER,
        replay: new MemoryRateLimiter(),
      }),
    },
    serviceAuth: createParcAuth({
      issuer: config.JWT_ISSUER,
      audience: config.SERVICE_NAME,
      allowPlatformTenant: true,
      keys: (header) => {
        const key = header.kid ? keys.publicKeys.get(header.kid) : undefined;
        if (!key) throw new Error("unknown key");
        return key;
      },
    }),
  });
  const assertion = (client: string, kid: string, key: Key) =>
    new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuer(client)
      .setSubject(client)
      .setAudience(config.JWT_ISSUER)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(key);
  const tokenRequest = async (
    client: "parc-lending" | "parc-mobile-bff",
    fields: Record<string, string>,
  ) =>
    request(app)
      .post("/internal/v1/oauth/token")
      .type("form")
      .send({
        grant_type: "client_credentials",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: await assertion(
          client,
          client === "parc-lending" ? "l1" : "m1",
          client === "parc-lending"
            ? clientKeys.lending.privateKey
            : clientKeys.mobile.privateKey,
        ),
        tenant_id: tenantId,
        ...fields,
      });
  return { app, tokenRequest };
}

describe("service token endpoint and internal route policies", () => {
  it("issues a token that the internal route then authorizes", async () => {
    const { app, tokenRequest } = await harness();
    const issued = await tokenRequest("parc-lending", {
      audience: "parc-auth-customer",
      scope: "auth.lending-eligibility.read",
    });
    expect(issued.status).toBe(200);
    expect(issued.headers["cache-control"]).toBe("no-store");
    const token = (issued.body as { access_token: string }).access_token;
    const path = `/internal/v1/tenants/${tenantId}/customers/${customerId}/lending-eligibility?consent_reference=${consentReference}`;
    await request(app)
      .get(path)
      .set("authorization", `Bearer ${token}`)
      .expect(200, { eligible: true });
    await request(app).get(path).expect(401);
    await request(app)
      .get(path)
      .set("authorization", `Bearer ${token}`)
      .set("x-tenant-id", customerId)
      .expect(403);
  });

  it("enforces the route's allowed callers even with a valid token", async () => {
    const { app, tokenRequest } = await harness();
    const issued = await tokenRequest("parc-mobile-bff", {
      audience: "parc-tenant-admin",
      scope: "tenant.mobile-bootstrap.read",
    });
    expect(issued.status).toBe(200);
    // A token for another audience is never accepted by Auth's routes.
    await request(app)
      .get(
        `/internal/v1/tenants/${tenantId}/customers/${customerId}/lending-eligibility?consent_reference=${consentReference}`,
      )
      .set(
        "authorization",
        `Bearer ${(issued.body as { access_token: string }).access_token}`,
      )
      .expect(401);
  });

  it("returns OAuth errors for bad clients, scopes and requests", async () => {
    const { app, tokenRequest } = await harness();
    expect(
      (
        await tokenRequest("parc-lending", {
          audience: "parc-ledger",
          scope: "ledger.adjustments.write",
        })
      ).body,
    ).toMatchObject({ error: "invalid_scope" });
    const badClient = await request(app)
      .post("/internal/v1/oauth/token")
      .type("form")
      .send({
        grant_type: "client_credentials",
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: "eyJhbGciOiJFUzI1NiJ9.e30.invalid-signature",
        audience: "parc-ledger",
        scope: "ledger.postings.write",
        tenant_id: tenantId,
      });
    expect(badClient.status).toBe(401);
    expect(badClient.body).toMatchObject({ error: "invalid_client" });
    expect(
      (
        await tokenRequest("parc-lending", {
          audience: "parc-ledger",
          scope: "ledger.postings.write",
          grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        })
      ).body,
    ).toMatchObject({ error: "invalid_request" });
  });
});
