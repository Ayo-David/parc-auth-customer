import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { principalOf } from "../security/parc-service-auth.js";
import type { LendingEligibilityService } from "../services/lending-eligibility-service.js";
import { ApiError } from "./api-error.js";

export function createLendingEligibilityRouter(
  service: LendingEligibilityService,
  eligibilityAccess: RequestHandler,
): Router {
  const router = Router();
  router.get(
    "/internal/v1/tenants/:tenantId/customers/:customerId/lending-eligibility",
    eligibilityAccess,
    async (request, response, next) => {
      try {
        const principal = principalOf(request);
        const tenantId = z.string().uuid().parse(request.params.tenantId);
        const customerId = z.string().uuid().parse(request.params.customerId);
        if (principal.tenantId !== tenantId)
          throw new ApiError(403, "TENANT_MISMATCH", "Tenant context mismatch");
        // A customer delegation may only read that customer's own evidence.
        if (
          principal.subject?.type === "CUSTOMER" &&
          principal.subject.id !== customerId
        )
          throw new ApiError(403, "SUBJECT_MISMATCH", "Customer mismatch");
        response.json(
          await service.get({
            tenantId,
            customerId,
            consentReference: z
              .string()
              .uuid()
              .parse(request.query.consent_reference),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
