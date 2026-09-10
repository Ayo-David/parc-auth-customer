import { randomUUID } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";
import type { KycService } from "../services/kyc-service.js";
import { ApiError } from "./api-error.js";

const requestSchema = z
  .object({
    identity_type: z.enum(["NIN", "BVN"]),
    identity_value: z.string().regex(/^[0-9]{11}$/),
    consent_id: z.string().uuid(),
  })
  .strict();

function requiredHeader(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}

function requiredIdentity(
  identity?: AuthenticatedCustomer,
): AuthenticatedCustomer {
  if (!identity)
    throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
  return identity;
}

export function createKycRouter(
  kyc: KycService,
  authenticate: RequestHandler,
): Router {
  const router = Router();
  router.post(
    "/v1/kyc/verifications",
    authenticate,
    async (request, response, next) => {
      try {
        const identity = requiredIdentity(request.authenticatedCustomer);
        const input = requestSchema.parse(request.body);
        const correlation = z
          .string()
          .uuid()
          .safeParse(request.header("x-correlation-id"));
        response.status(202).json(
          await kyc.start({
            tenantId: identity.tenantId,
            userId: identity.subject,
            identityType: input.identity_type,
            identityValue: input.identity_value,
            consentId: input.consent_id,
            idempotencyKey: requiredHeader(request, "idempotency-key"),
            correlationId: correlation.success
              ? correlation.data
              : randomUUID(),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.get(
    "/v1/kyc/verifications/:id",
    authenticate,
    async (request, response, next) => {
      try {
        const identity = requiredIdentity(request.authenticatedCustomer);
        const verificationId = z.string().uuid().parse(request.params.id);
        response
          .status(200)
          .json(
            await kyc.get(identity.tenantId, identity.subject, verificationId),
          );
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
