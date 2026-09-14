import { Router, type RequestHandler } from "express";
import { z } from "zod";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";
import type { CustomerExperienceService } from "../services/customer-experience-service.js";
import { ApiError } from "./api-error.js";

export function createCustomerExperienceRouter(
  service: CustomerExperienceService,
  authenticate: RequestHandler,
): Router {
  const router = Router();
  router.use("/v1/security", authenticate);
  router.use("/v1/notifications", authenticate);
  router.use("/v1/referrals/summary", authenticate);
  router.get("/v1/security", async (request, response, next) => {
    try {
      const identity = required(request.authenticatedCustomer);
      response.json(
        await service.security(identity.tenantId, identity.subject),
      );
    } catch (error) {
      next(error);
    }
  });
  router.get("/v1/notifications", async (request, response, next) => {
    try {
      const identity = required(request.authenticatedCustomer);
      const pageSize = z.coerce
        .number()
        .int()
        .min(1)
        .max(100)
        .default(20)
        .parse(request.query.page_size);
      response.json(
        await service.notifications(
          identity.tenantId,
          identity.subject,
          pageSize,
        ),
      );
    } catch (error) {
      next(error);
    }
  });
  router.get("/v1/referrals/summary", async (request, response, next) => {
    try {
      const identity = required(request.authenticatedCustomer);
      response.json(
        await service.referralSummary(identity.tenantId, identity.subject),
      );
    } catch (error) {
      next(error);
    }
  });
  return router;
}
function required(identity?: AuthenticatedCustomer): AuthenticatedCustomer {
  if (!identity)
    throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
  return identity;
}
