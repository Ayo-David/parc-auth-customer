import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import type { NextFunction, Request, Response } from "express";
import {
  createLocalJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  SignJWT,
  type JWTPayload,
} from "jose";
import {
  createParcAuth,
  currentPrincipal,
  ParcTokenClient,
  runAsService,
  type ParcPrincipal,
} from "../../src/security/parc-service-auth.js";

const issuer = "https://auth.parc.invalid";
const tenantId = "11111111-1111-4111-8111-111111111111";
const otherTenant = "22222222-2222-4222-8222-222222222222";
const sessionId = "33333333-3333-4333-8333-333333333333";
const customerId = "44444444-4444-4444-8444-444444444444";

type Signer = Awaited<ReturnType<typeof generateKeyPair>>;
let auth: Signer;
let jwks: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  auth = await generateKeyPair("RS256");
  jwks = createLocalJWKSet({
    keys: [{ ...(await exportJWK(auth.publicKey)), kid: "k1", alg: "RS256" }],
  });
});

function sign(claims: JWTPayload, audience = "parc-test"): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setJti(randomUUID())
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(auth.privateKey);
}

const serviceClaims = {
  sub: "parc-worker",
  client_id: "parc-worker",
  token_use: "service",
  tenant_id: tenantId,
  scope: "test.jobs.run",
};
const delegatedClaims = {
  sub: customerId,
  client_id: "parc-mobile-bff",
  token_use: "delegated",
  tenant_id: tenantId,
  scope: "test.customer.read test.customer.write",
  subject_type: "CUSTOMER",
  session_id: sessionId,
  act: { sub: "parc-mobile-bff" },
};

interface Outcome {
  status?: number;
  body?: unknown;
  headers: Record<string, string>;
  next: boolean;
  principal?: ParcPrincipal;
  context?: ParcPrincipal;
}

function run(
  handler: (request: Request, response: Response, next: NextFunction) => void,
  headers: Record<string, string>,
): Promise<Outcome> {
  return new Promise((resolve) => {
    const outcome: Outcome = { headers: {}, next: false };
    const request = {
      header: (name: string) => headers[name.toLowerCase()],
    } as unknown as Request;
    const response = {
      setHeader(name: string, value: string) {
        outcome.headers[name.toLowerCase()] = value;
        return this;
      },
      status(code: number) {
        outcome.status = code;
        return this;
      },
      json(body: unknown) {
        outcome.body = body;
        resolve(outcome);
        return this;
      },
    } as unknown as Response;
    handler(request, response, (error?: unknown) => {
      if (error !== undefined) throw error as Error;
      outcome.next = true;
      if (request.parcPrincipal) outcome.principal = request.parcPrincipal;
      const context = currentPrincipal();
      if (context) outcome.context = context;
      resolve(outcome);
    });
  });
}

describe("parc-service-auth inbound validation", () => {
  const parcAuth = () =>
    createParcAuth({ issuer, audience: "parc-test", keys: jwks });

  it("accepts a delegated token and exposes user and acting service", async () => {
    const token = await sign({
      ...delegatedClaims,
      client_id: "parc-savings",
      act: { sub: "parc-savings", act: { sub: "parc-mobile-bff" } },
    });
    const outcome = await run(
      parcAuth().require({
        scopes: ["test.customer.read"],
        kinds: ["delegated"],
        subjectTypes: ["CUSTOMER"],
        actors: ["parc-savings"],
      }),
      { authorization: `Bearer ${token}`, "x-tenant-id": tenantId },
    );
    expect(outcome.next).toBe(true);
    expect(outcome.principal).toMatchObject({
      kind: "delegated",
      tenantId,
      client: "parc-savings",
      actors: ["parc-savings", "parc-mobile-bff"],
      subject: { id: customerId, type: "CUSTOMER", sessionId },
    });
    expect(outcome.context?.token).toBe(token);
  });

  it("accepts a service token for service-only operations", async () => {
    const outcome = await run(
      parcAuth().require({ scopes: ["test.jobs.run"], kinds: ["service"] }),
      { authorization: `Bearer ${await sign(serviceClaims)}` },
    );
    expect(outcome.next).toBe(true);
    expect(outcome.principal).toMatchObject({
      kind: "service",
      client: "parc-worker",
      actors: [],
    });
    expect(outcome.principal?.subject).toBeUndefined();
  });

  it.each([
    ["no header", {}],
    ["legacy header", { "x-internal-service-token": "secret" }],
    ["basic scheme", { authorization: "Basic abc" }],
    ["garbage token", { authorization: "Bearer not.a.jwt" }],
  ])("rejects %s with 401", async (_name, headers: Record<string, string>) => {
    const outcome = await run(
      parcAuth().require({ scopes: ["test.jobs.run"] }),
      headers,
    );
    expect(outcome.status).toBe(401);
    expect(outcome.headers["www-authenticate"]).toMatch(/^Bearer /);
  });

  it("rejects tokens for another audience, a user access token, and a foreign signer", async () => {
    const foreign = await generateKeyPair("RS256");
    const candidates = [
      await sign(serviceClaims, "parc-other"),
      await sign({
        sub: customerId,
        tenant_id: tenantId,
        session_id: sessionId,
        subject_type: "CUSTOMER",
      }),
      await new SignJWT(serviceClaims)
        .setProtectedHeader({ alg: "RS256", kid: "k1" })
        .setIssuer(issuer)
        .setAudience("parc-test")
        .setJti(randomUUID())
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(foreign.privateKey),
    ];
    for (const token of candidates)
      expect(
        (
          await run(parcAuth().require({ scopes: [] }), {
            authorization: `Bearer ${token}`,
          })
        ).status,
      ).toBe(401);
  });

  it("rejects inconsistent claims", async () => {
    const candidates = [
      { ...serviceClaims, sub: "parc-other" },
      { ...serviceClaims, act: { sub: "parc-worker" } },
      { ...delegatedClaims, act: { sub: "parc-other" } },
      { ...delegatedClaims, session_id: undefined },
      { ...delegatedClaims, tenant_id: null },
      { ...serviceClaims, tenant_id: null },
      { ...serviceClaims, scope: "UPPER.case" },
    ];
    for (const claims of candidates)
      expect(
        (
          await run(parcAuth().require({ scopes: [] }), {
            authorization: `Bearer ${await sign(claims)}`,
          })
        ).status,
      ).toBe(401);
  });

  it("accepts tenantless platform tokens only when the service opts in", async () => {
    const platform = createParcAuth({
      issuer,
      audience: "parc-test",
      keys: jwks,
      allowPlatformTenant: true,
    });
    const admin = await sign({
      ...delegatedClaims,
      subject_type: "ADMINISTRATOR",
      tenant_id: null,
    });
    const service = await sign({ ...serviceClaims, tenant_id: null });
    const customer = await sign({ ...delegatedClaims, tenant_id: null });
    for (const token of [admin, service])
      expect(
        (
          await run(platform.require({ scopes: [] }), {
            authorization: `Bearer ${token}`,
          })
        ).principal?.tenantId,
      ).toBeNull();
    expect(
      (
        await run(platform.require({ scopes: [] }), {
          authorization: `Bearer ${customer}`,
        })
      ).status,
    ).toBe(401);
  });

  it("enforces tenant and calling-service header agreement", async () => {
    const token = await sign(delegatedClaims);
    expect(
      (
        await run(parcAuth().require({ scopes: [] }), {
          authorization: `Bearer ${token}`,
          "x-tenant-id": otherTenant,
        })
      ).body,
    ).toMatchObject({ code: "TENANT_MISMATCH" });
    expect(
      (
        await run(parcAuth().require({ scopes: [] }), {
          authorization: `Bearer ${token}`,
          "x-calling-service": "parc-admin-bff",
        })
      ).body,
    ).toMatchObject({ code: "CALLER_MISMATCH" });
  });

  it.each([
    [{ scopes: ["test.jobs.run"] }, "INSUFFICIENT_SCOPE"],
    [{ scopes: [], kinds: ["service"] as const }, "TOKEN_KIND_FORBIDDEN"],
    [
      { scopes: [], subjectTypes: ["ADMINISTRATOR"] as const },
      "SUBJECT_FORBIDDEN",
    ],
    [{ scopes: [], actors: ["parc-admin-bff"] }, "CALLER_FORBIDDEN"],
  ])("enforces endpoint policy %p", async (policy, code) => {
    const outcome = await run(parcAuth().require(policy), {
      authorization: `Bearer ${await sign(delegatedClaims)}`,
    });
    expect(outcome.status).toBe(403);
    expect(outcome.body).toMatchObject({ code });
  });
});

describe("parc-service-auth token client", () => {
  async function client() {
    const keys = await generateKeyPair("ES256");
    const fetchMock = jest.fn<typeof fetch>(() =>
      Promise.resolve(
        Response.json({
          access_token: "issued-token",
          issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
          token_type: "Bearer",
          expires_in: 300,
          scope: "test.jobs.run",
        }),
      ),
    );
    const tokens = new ParcTokenClient({
      tokenUrl: "http://auth.test/internal/v1/oauth/token",
      issuer,
      clientId: "parc-test",
      keyId: "parc-test-1",
      privateKey: keys.privateKey,
      fetch: fetchMock,
    });
    return { tokens, fetchMock, keys };
  }
  const form = (call: Parameters<typeof fetch> | undefined) =>
    new URLSearchParams(call?.[1]?.body as URLSearchParams);

  it("requests a service-only token with a signed client assertion", async () => {
    const { tokens, fetchMock, keys } = await client();
    await expect(
      tokens.authorization({
        audience: "parc-ledger",
        scopes: ["ledger.postings.write"],
        tenantId,
      }),
    ).resolves.toBe("Bearer issued-token");
    const body = form(fetchMock.mock.calls[0]);
    expect(body.get("grant_type")).toBe("client_credentials");
    expect(body.get("subject_token")).toBeNull();
    expect(body.get("tenant_id")).toBe(tenantId);
    const { payload } = await jwtVerify(
      body.get("client_assertion") ?? "",
      keys.publicKey,
      { issuer: "parc-test", subject: "parc-test", audience: issuer },
    );
    expect((payload.exp ?? 0) - (payload.iat ?? 0)).toBeLessThanOrEqual(60);
  });

  it("exchanges the inbound delegated token and caches by subject", async () => {
    const { tokens, fetchMock } = await client();
    const parcAuth = createParcAuth({
      issuer,
      audience: "parc-test",
      keys: jwks,
    });
    const inbound = await sign(delegatedClaims);
    const request = {
      audience: "parc-ledger",
      scopes: ["ledger.balances.read"],
      tenantId,
    };
    await new Promise<void>((resolve, reject) => {
      parcAuth.authenticate()(
        {
          header: (name: string) =>
            name === "authorization" ? `Bearer ${inbound}` : undefined,
        } as unknown as Request,
        {} as Response,
        () => {
          void (async () => {
            await tokens.token(request);
            await tokens.token(request);
            await runAsService(() => tokens.token(request));
          })().then(resolve, reject);
        },
      );
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const delegated = form(fetchMock.mock.calls[0]);
    expect(delegated.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    expect(delegated.get("subject_token")).toBe(inbound);
    expect(form(fetchMock.mock.calls[1]).get("grant_type")).toBe(
      "client_credentials",
    );
  });

  it("uses an explicit subject token and requests platform tokens without a tenant", async () => {
    const { tokens, fetchMock } = await client();
    const userToken = await sign({ sub: customerId }, "parc-mobile-bff");
    await tokens.token({
      audience: "parc-tenant-admin",
      scopes: ["tenant.administration"],
      tenantId: null,
      subjectToken: userToken,
    });
    const body = form(fetchMock.mock.calls[0]);
    expect(body.get("subject_token")).toBe(userToken);
    expect(body.get("tenant_id")).toBe("platform");
    expect(decodeJwt(body.get("client_assertion") ?? "").iss).toBe("parc-test");
  });

  it("refuses to fall back to a service token when delegation is required", async () => {
    const { tokens } = await client();
    await expect(
      tokens.token({
        audience: "parc-ledger",
        scopes: ["ledger.balances.read"],
        tenantId,
        mode: "delegated",
      }),
    ).rejects.toThrow("no_delegated_subject");
  });

  it("surfaces OAuth errors without leaking credentials", async () => {
    const { tokens, fetchMock } = await client();
    fetchMock.mockResolvedValueOnce(
      Response.json({ error: "invalid_scope" }, { status: 400 }),
    );
    await expect(
      tokens.token({ audience: "parc-ledger", scopes: ["x.y"], tenantId }),
    ).rejects.toThrow("Service token request failed (400 invalid_scope)");
  });
});
