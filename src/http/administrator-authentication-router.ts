import { timingSafeEqual } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { ApiError } from "./api-error.js";
import type { AdministratorAuthenticationService } from "../services/administrator-authentication-service.js";

const scopeFields = {
  tenant_id: z.string().uuid().nullable(),
  scope: z.enum(["TENANT", "PLATFORM"]),
};
const loginSchema = z
  .object({
    identifier: z.string().min(3).max(254),
    password: z.string().min(1).max(128),
    tenant_context: z.string().uuid().nullable(),
  })
  .strict();
const verifySchema = z
  .object({
    ...scopeFields,
    challenge_id: z.string().uuid(),
    response: z.string().min(1).max(4096),
  })
  .strict();
const enrollmentSchema = z
  .object({
    administrator_id: z.string().uuid(),
    ...scopeFields,
    method: z.enum(["TOTP", "SMS_OTP", "EMAIL_OTP", "PASSKEY"]),
    identifier: z.string().min(3).max(254).optional(),
    bootstrap_token: z.string().min(32).optional(),
  })
  .strict();
const resetSchema = z
  .object({
    administrator_id: z.string().uuid(),
    ...scopeFields,
    method: z.enum(["TOTP", "SMS_OTP", "EMAIL_OTP", "PASSKEY"]),
    approval_id: z.string().uuid(),
    reason: z.string().min(3).max(500),
  })
  .strict();

function authorize(value: string | undefined, expected: string): void {
  const supplied = value?.startsWith("Bearer ") ? value.slice(7) : "";
  const left = Buffer.from(supplied);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right))
    throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
}

function idempotencyKey(value: string | undefined): string {
  if (!value)
    throw new ApiError(400, "INVALID_REQUEST", "idempotency-key is required");
  return value;
}

function validateScope(input: {
  tenant_id: string | null;
  scope: "TENANT" | "PLATFORM";
}): void {
  if ((input.scope === "TENANT") !== Boolean(input.tenant_id))
    throw new ApiError(
      400,
      "INVALID_SCOPE",
      "Tenant and platform scopes cannot be mixed",
    );
}

export function createAdministratorAuthenticationRouter(
  service: AdministratorAuthenticationService,
  serviceToken: string,
): Router {
  const router = Router();
  router.use("/internal/v1", (request, _response, next) => {
    try {
      authorize(request.header("authorization"), serviceToken);
      next();
    } catch (error) {
      next(error);
    }
  });
  router.post(
    "/internal/v1/admin-authenticate",
    async (request, response, next) => {
      try {
        const input = loginSchema.parse(request.body);
        response.status(200).json(
          await service.authenticate({
            identifier: input.identifier,
            password: input.password,
            tenantContext: input.tenant_context,
            idempotencyKey: idempotencyKey(request.header("idempotency-key")),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-mfa/verify",
    async (request, response, next) => {
      try {
        idempotencyKey(request.header("idempotency-key"));
        const input = verifySchema.parse(request.body);
        validateScope(input);
        response.status(200).json(
          await service.verify({
            tenantId: input.tenant_id,
            scope: input.scope,
            challengeId: input.challenge_id,
            response: input.response,
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-mfa/enrollments",
    async (request, response, next) => {
      try {
        idempotencyKey(request.header("idempotency-key"));
        const input = enrollmentSchema.parse(request.body);
        validateScope(input);
        response.status(201).json(
          await service.enroll({
            administratorId: input.administrator_id,
            tenantId: input.tenant_id,
            scope: input.scope,
            method: input.method,
            ...(input.identifier ? { identifier: input.identifier } : {}),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-mfa/resets",
    async (request, response, next) => {
      try {
        const requestKey = idempotencyKey(request.header("idempotency-key"));
        const input = resetSchema.parse(request.body);
        validateScope(input);
        await service.reset({
          administratorId: input.administrator_id,
          tenantId: input.tenant_id,
          scope: input.scope,
          method: input.method,
          approvalId: input.approval_id,
          reason: input.reason,
          idempotencyKey: requestKey,
        });
        response.status(202).send();
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
