import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import express, { type RequestHandler } from "express";
import request from "supertest";
import { createCustomerProviderProfileRouter } from "../../src/http/customer-provider-profile-router.js";
import type { CustomerService } from "../../src/services/customer-service.js";

const tenantId = randomUUID();
const customerId = randomUUID();
const profile = {
  customer_id: customerId,
  first_name: "Ayo",
  middle_name: "David",
  last_name: "Ajayi",
  email: "ayo@example.com",
  phone_number: "+2348000000000",
  bvn: "22222222222",
};

function app(principalTenantId: string) {
  const providerProfile = jest.fn(() => Promise.resolve(profile));
  const access: RequestHandler = (req, _res, next) => {
    req.parcPrincipal = {
      kind: "service",
      tenantId: principalTenantId,
      scopes: new Set(["auth.customer-provider-profile.read"]),
      client: "parc-payment",
      actors: [],
      token: "token",
      expiresAt: Date.now() / 1000 + 60,
    } as never;
    next();
  };
  const server = express();
  server.use(
    createCustomerProviderProfileRouter(
      { providerProfile } as unknown as CustomerService,
      access,
    ),
  );
  server.use(
    (
      error: { status?: number; code?: string },
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => res.status(error.status ?? 500).json({ code: error.code }),
  );
  return { server, providerProfile };
}

const path = `/internal/v1/tenants/${tenantId}/customers/${customerId}/provider-profile`;

test("returns the verified customer's provider profile without caching", async () => {
  const { server, providerProfile } = app(tenantId);
  const response = await request(server).get(path);
  expect(response.status).toBe(200);
  expect(response.body).toEqual(profile);
  expect(response.headers["cache-control"]).toBe("no-store");
  expect(providerProfile).toHaveBeenCalledWith(tenantId, customerId);
});

test("refuses a token issued for another tenant", async () => {
  const { server, providerProfile } = app(randomUUID());
  const response = await request(server).get(path);
  expect(response.status).toBe(403);
  expect(providerProfile).not.toHaveBeenCalled();
});
