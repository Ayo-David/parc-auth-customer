import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import { decodeJwt, SignJWT, type JWTPayload } from "jose";
import {
  createJwtKeyRing,
  type JwtKeyRing,
} from "../../src/security/jwt-key-ring.js";
import { scopeCatalogue } from "../../src/security/scope-catalogue.js";
import {
  ServiceTokenService,
  type ServiceTokenRequest,
  type SubjectSessions,
} from "../../src/services/service-token-service.js";
import type { TenantStatus } from "../../src/services/tenant-admin-client.js";

const issuer = "https://auth.parc.invalid";
const tenantId = "11111111-1111-4111-8111-111111111111";
const otherTenant = "22222222-2222-4222-8222-222222222222";
const customerId = "33333333-3333-4333-8333-333333333333";
const administratorId = "44444444-4444-4444-8444-444444444444";
const sessionId = "55555555-5555-4555-8555-555555555555";

let keys: JwtKeyRing;
beforeAll(async () => {
  keys = await createJwtKeyRing({ activeKid: "test" });
});

function setup(
  overrides: {
    status?: TenantStatus;
    permissions?: string[];
    introspection?: object;
    sessionActive?: boolean;
  } = {},
) {
  const getTenantStatus = jest.fn((_tenant: string) =>
    Promise.resolve(overrides.status ?? "ACTIVE"),
  );
  const getAdministratorAuthorization = jest.fn((_id: string) =>
    Promise.resolve({
      roles: ["operator"],
      permissions: overrides.permissions ?? [],
      authorization_version: 1,
    }),
  );
  const introspect = jest.fn<SubjectSessions["introspect"]>(() =>
    Promise.resolve(
      overrides.introspection ?? {
        active: true,
        subject: customerId,
        tenant_id: tenantId,
        subject_type: "CUSTOMER",
        scope: "TENANT",
        session_id: sessionId,
      },
    ),
  );
  const sessionActive = jest.fn<SubjectSessions["sessionActive"]>(() =>
    Promise.resolve(overrides.sessionActive ?? true),
  );
  const service = new ServiceTokenService({
    keys,
    issuer,
    catalogue: scopeCatalogue,
    tenants: { getTenantStatus },
    administrators: { getAdministratorAuthorization },
    sessions: { introspect, sessionActive },
  });
  return {
    service,
    getTenantStatus,
    getAdministratorAuthorization,
    introspect,
    sessionActive,
  };
}

function userToken(audience: string | string[], claims: JWTPayload = {}) {
  return new SignJWT({ tenant_id: tenantId, session_id: sessionId, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: keys.activeKid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(customerId)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(keys.privateKey);
}

const serviceRequest: ServiceTokenRequest = {
  client: "parc-savings",
  grant: "client_credentials",
  audience: "parc-ledger",
  scopes: ["ledger.postings.write"],
  tenantId,
};

async function failure(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    return error as { status: number; error: string };
  }
  throw new Error("Expected the token request to be refused");
}

describe("service-only tokens", () => {
  it("issues an audience-bound, short-lived service token", async () => {
    const { service } = setup();
    const issued = await service.issue(serviceRequest);
    const claims = decodeJwt(issued.access_token);
    expect(issued).toMatchObject({
      token_type: "Bearer",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      scope: "ledger.postings.write",
    });
    expect(issued.expires_in).toBeLessThanOrEqual(300);
    expect(claims).toMatchObject({
      iss: issuer,
      aud: "parc-ledger",
      sub: "parc-savings",
      client_id: "parc-savings",
      token_use: "service",
      tenant_id: tenantId,
    });
    expect(claims.act).toBeUndefined();
    expect(claims.session_id).toBeUndefined();
  });

  it.each([
    [{ client: "parc-unknown" }, 401, "invalid_client"],
    [{ scopes: ["ledger.adjustments.write"] }, 400, "invalid_scope"],
    [{ scopes: ["savings.customer.read"] }, 400, "invalid_scope"],
    [{ audience: "parc-payment" }, 400, "invalid_scope"],
    [
      { client: "parc-ledger", scopes: ["ledger.postings.write"] },
      400,
      "invalid_request",
    ],
    [{ scopes: [] }, 400, "invalid_scope"],
  ])(
    "refuses a request outside the caller's policy %p",
    async (change, status, code) => {
      const { service } = setup();
      expect(
        await failure(service.issue({ ...serviceRequest, ...change })),
      ).toMatchObject({
        status,
        error: code,
      });
    },
  );

  it("refuses inactive tenants and tenantless non-platform scopes", async () => {
    expect(
      await failure(
        setup({ status: "SUSPENDED" }).service.issue(serviceRequest),
      ),
    ).toMatchObject({ error: "invalid_grant" });
    expect(
      await failure(
        setup().service.issue({ ...serviceRequest, tenantId: null }),
      ),
    ).toMatchObject({ error: "invalid_scope" });
  });

  it("signs Auth's own platform tokens locally and caches them", async () => {
    const { service, getTenantStatus } = setup();
    const input = {
      audience: "parc-tenant-admin",
      scopes: ["tenant.administrators.authenticate"],
      tenantId: null,
    };
    const first = await service.authorization(input);
    expect(await service.authorization(input)).toBe(first);
    expect(decodeJwt(first.slice("Bearer ".length))).toMatchObject({
      sub: "parc-auth-customer",
      tenant_id: null,
      token_use: "service",
    });
    expect(getTenantStatus).not.toHaveBeenCalled();
    await expect(
      service.authorization({ ...input, scopes: ["ledger.postings.write"] }),
    ).rejects.toMatchObject({ error: "invalid_scope" });
  });
});

describe("delegated tokens", () => {
  const exchange = (subjectToken: string): ServiceTokenRequest => ({
    client: "parc-mobile-bff",
    grant: "token_exchange",
    audience: "parc-savings",
    scopes: ["savings.customer.read"],
    tenantId,
    subjectToken,
  });

  it("exchanges a customer's access token for the BFF that owns it", async () => {
    const { service, introspect } = setup();
    const issued = await service.issue(exchange(await userToken("mobile-bff")));
    expect(introspect).toHaveBeenCalledWith(expect.any(String), "mobile-bff");
    expect(decodeJwt(issued.access_token)).toMatchObject({
      aud: "parc-savings",
      sub: customerId,
      client_id: "parc-mobile-bff",
      token_use: "delegated",
      subject_type: "CUSTOMER",
      subject_scope: "TENANT",
      session_id: sessionId,
      act: { sub: "parc-mobile-bff" },
    });
  });

  it("refuses a user token presented by a service it was not issued to", async () => {
    const { service } = setup();
    const token = await userToken("mobile-bff");
    expect(
      await failure(
        service.issue({
          ...exchange(token),
          client: "parc-lending",
          audience: "parc-ledger",
          scopes: ["ledger.postings.write"],
        }),
      ),
    ).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses an inactive session, another tenant, and a forged token", async () => {
    const inactive = setup({ introspection: { active: false } });
    expect(
      await failure(
        inactive.service.issue(exchange(await userToken("mobile-bff"))),
      ),
    ).toMatchObject({ error: "invalid_grant" });
    expect(
      await failure(
        setup().service.issue({
          ...exchange(await userToken("mobile-bff")),
          tenantId: otherTenant,
        }),
      ),
    ).toMatchObject({ error: "invalid_grant" });
    const foreign = await createJwtKeyRing({ activeKid: keys.activeKid });
    const forged = await new SignJWT({ tenant_id: tenantId })
      .setProtectedHeader({ alg: "RS256", kid: keys.activeKid })
      .setIssuer(issuer)
      .setAudience("mobile-bff")
      .setSubject(customerId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(foreign.privateKey);
    expect(
      await failure(setup().service.issue(exchange(forged))),
    ).toMatchObject({
      error: "invalid_grant",
    });
  });

  it("refuses scopes the customer is not entitled to delegate", async () => {
    const { service } = setup();
    expect(
      await failure(
        service.issue({
          ...exchange(await userToken("mobile-bff")),
          scopes: ["savings.operations.process"],
        }),
      ),
    ).toMatchObject({ error: "invalid_scope" });
  });

  it("requires administrators to hold the mapped Tenant Admin permission", async () => {
    const admin = {
      active: true,
      subject: administratorId,
      tenant_id: tenantId,
      subject_type: "ADMINISTRATOR",
      scope: "TENANT",
      session_id: sessionId,
    };
    const request = async (): Promise<ServiceTokenRequest> => ({
      client: "parc-admin-bff",
      grant: "token_exchange",
      audience: "parc-savings",
      scopes: ["savings.products.publish"],
      tenantId,
      subjectToken: await userToken("admin-bff"),
    });
    const denied = setup({
      introspection: admin,
      permissions: ["savings.product.manage"],
    });
    expect(await failure(denied.service.issue(await request()))).toMatchObject({
      error: "invalid_scope",
    });
    const allowed = setup({
      introspection: admin,
      permissions: ["savings.product.publish"],
    });
    const issued = await allowed.service.issue(await request());
    expect(allowed.getAdministratorAuthorization).toHaveBeenCalledWith(
      administratorId,
    );
    expect(decodeJwt(issued.access_token)).toMatchObject({
      subject_type: "ADMINISTRATOR",
      act: { sub: "parc-admin-bff" },
    });
  });

  it("lets platform administrators act on a tenant or without one", async () => {
    const { service } = setup({
      introspection: {
        active: true,
        subject: administratorId,
        tenant_id: null,
        subject_type: "ADMINISTRATOR",
        scope: "PLATFORM",
        session_id: sessionId,
      },
    });
    const subjectToken = await userToken("admin-bff", { tenant_id: null });
    const issued = await service.issue({
      client: "parc-admin-bff",
      grant: "token_exchange",
      audience: "parc-tenant-admin",
      scopes: ["tenant.administration"],
      tenantId: null,
      subjectToken,
    });
    expect(decodeJwt(issued.access_token)).toMatchObject({
      tenant_id: null,
      subject_scope: "PLATFORM",
    });
  });

  it("re-exchanges a delegated token along a service chain", async () => {
    const { service, sessionActive } = setup();
    const first = await service.issue(exchange(await userToken("mobile-bff")));
    const chained = setup();
    const savingsRequest: ServiceTokenRequest = {
      client: "parc-savings",
      grant: "token_exchange",
      audience: "parc-ledger",
      scopes: ["ledger.postings.write"],
      tenantId,
      subjectToken: first.access_token,
    };
    const second = await chained.service.issue(savingsRequest);
    expect(chained.sessionActive).toHaveBeenCalledWith({
      tenantId,
      scope: "TENANT",
      sessionId,
      subjectId: customerId,
      subjectType: "CUSTOMER",
    });
    expect(sessionActive).not.toHaveBeenCalled();
    expect(decodeJwt(second.access_token)).toMatchObject({
      aud: "parc-ledger",
      sub: customerId,
      client_id: "parc-savings",
      act: { sub: "parc-savings", act: { sub: "parc-mobile-bff" } },
    });
    expect(second.expires_in).toBeLessThanOrEqual(first.expires_in);

    expect(
      await failure(
        chained.service.issue({ ...savingsRequest, client: "parc-lending" }),
      ),
    ).toMatchObject({ error: "invalid_grant" });
    expect(
      await failure(
        setup({ sessionActive: false }).service.issue(savingsRequest),
      ),
    ).toMatchObject({ error: "invalid_grant" });
  });

  it("refuses a service token as a subject", async () => {
    const { service } = setup();
    const serviceToken = await service.issue({
      ...serviceRequest,
      client: "parc-mobile-bff",
      audience: "parc-tenant-admin",
      scopes: ["tenant.mobile-bootstrap.read"],
    });
    expect(
      await failure(service.issue(exchange(serviceToken.access_token))),
    ).toMatchObject({ error: "invalid_grant" });
  });
});
