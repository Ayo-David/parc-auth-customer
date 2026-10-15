import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { principalOf } from "../security/parc-service-auth.js";
import type { CustomerService } from "../services/customer-service.js";
import { ApiError } from "./api-error.js";

/** Payment-only: the details a provider needs to open an account in the customer's name. */
export function createCustomerProviderProfileRouter(
  service: CustomerService,
  providerProfileAccess: RequestHandler,
): Router {
  const router = Router();
  router.get(
    "/internal/v1/tenants/:tenantId/customers/:customerId/provider-profile",
    providerProfileAccess,
    async (request, response, next) => {
      try {
        const principal = principalOf(request);
        const tenantId = z.string().uuid().parse(request.params.tenantId);
        const customerId = z.string().uuid().parse(request.params.customerId);
        if (principal.tenantId !== tenantId)
          throw new ApiError(403, "TENANT_MISMATCH", "Tenant context mismatch");
        response.set("cache-control", "no-store");
        response.json(await service.providerProfile(tenantId, customerId));
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
