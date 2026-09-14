import { timingSafeEqual } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";
import type { TransactionAuthorizationService } from "../services/transaction-authorization-service.js";
import { ApiError } from "./api-error.js";

const issueSchema = z
  .object({
    command_type: z.string().min(1).max(80),
    resource_id: z.string().uuid(),
    request_hash: z.string().regex(/^[a-f0-9]{64}$/),
    method: z.enum(["transaction_pin", "biometric"]),
    pin: z
      .string()
      .regex(/^[0-9]{4}$/)
      .optional(),
    biometric_challenge_id: z.string().uuid().optional(),
    biometric_assertion: z.string().min(1).max(16_384).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.method === "transaction_pin" && !value.pin)
      context.addIssue({ code: "custom", message: "pin is required" });
    if (
      value.method === "biometric" &&
      (!value.biometric_challenge_id || !value.biometric_assertion)
    )
      context.addIssue({
        code: "custom",
        message: "biometric challenge and assertion are required",
      });
  });
const consumeSchema = z
  .object({
    authorization_token: z.string().min(32),
    customer_id: z.string().uuid(),
    command_type: z.string().min(1).max(80),
    resource_id: z.string().uuid(),
  })
  .strict();

function header(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}
function identity(value?: AuthenticatedCustomer): AuthenticatedCustomer {
  if (!value)
    throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
  return value;
}
function authorized(value: string | undefined, expected: string): boolean {
  const supplied = Buffer.from(
    value?.startsWith("Bearer ") ? value.slice(7) : "",
  );
  const expectedBuffer = Buffer.from(expected);
  return (
    supplied.length === expectedBuffer.length &&
    timingSafeEqual(supplied, expectedBuffer)
  );
}

export function createTransactionAuthorizationRouter(
  service: TransactionAuthorizationService,
  authenticate: RequestHandler,
  internalServiceToken: string,
): Router {
  const router = Router();
  router.post(
    "/v1/transaction-authorizations",
    authenticate,
    async (request, response, next) => {
      try {
        const actor = identity(request.authenticatedCustomer);
        const input = issueSchema.parse(request.body);
        response.status(201).json(
          await service.issue({
            tenantId: actor.tenantId,
            customerId: actor.subject,
            idempotencyKey: header(request, "idempotency-key"),
            commandType: input.command_type,
            resourceId: input.resource_id,
            requestHash: input.request_hash,
            method: input.method,
            ...(input.pin ? { pin: input.pin } : {}),
            ...(input.biometric_challenge_id
              ? { biometricChallengeId: input.biometric_challenge_id }
              : {}),
            ...(input.biometric_assertion
              ? { biometricAssertion: input.biometric_assertion }
              : {}),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/transaction-authorizations/consume",
    async (request, response, next) => {
      try {
        if (!authorized(request.header("authorization"), internalServiceToken))
          throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
        const input = consumeSchema.parse(request.body);
        response.status(200).json(
          await service.consume({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            customerId: input.customer_id,
            commandType: input.command_type,
            resourceId: input.resource_id,
            token: input.authorization_token,
            serviceName: header(request, "x-service-name"),
            idempotencyKey: header(request, "idempotency-key"),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
