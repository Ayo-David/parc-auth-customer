import { Router, type RequestHandler } from "express";
import { z } from "zod";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { ApiError } from "./api-error.js";
import type { PasskeyService } from "../services/passkey-service.js";

const transports = z.array(
  z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]),
);
const baseCredential = {
  id: z.string().min(1),
  rawId: z.string().min(1),
  type: z.literal("public-key"),
  authenticatorAttachment: z
    .enum(["platform", "cross-platform"])
    .nullable()
    .optional(),
  clientExtensionResults: z.record(z.unknown()),
};
const registrationCredential = z
  .object({
    ...baseCredential,
    response: z
      .object({
        clientDataJSON: z.string().min(1),
        attestationObject: z.string().min(1),
        authenticatorData: z.string().optional(),
        publicKey: z.string().optional(),
        publicKeyAlgorithm: z.number().int().optional(),
        transports: transports.optional(),
      })
      .strict(),
  })
  .strict();
const authenticationCredential = z
  .object({
    ...baseCredential,
    response: z
      .object({
        clientDataJSON: z.string().min(1),
        authenticatorData: z.string().min(1),
        signature: z.string().min(1),
        userHandle: z.string().optional(),
      })
      .strict(),
  })
  .strict();
const scopeSchema = z
  .object({
    tenant_id: z.string().uuid().nullable(),
    scope: z.enum(["TENANT", "PLATFORM"]),
  })
  .refine((input) => (input.scope === "TENANT") === Boolean(input.tenant_id));

function header(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}

export function createPasskeyRouter(
  service: PasskeyService,
  authenticateCustomer: RequestHandler,
  administratorAccess: RequestHandler,
): Router {
  const router = Router();
  router.post(
    "/v1/auth/passkeys/registration/options",
    authenticateCustomer,
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const input = z
          .object({ friendly_name: z.string().min(1).max(150).optional() })
          .strict()
          .parse(request.body);
        const identity = request.authenticatedCustomer;
        if (!identity)
          throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
        response
          .status(200)
          .json(
            await service.createCustomerRegistrationOptions(
              identity.tenantId,
              identity.subject,
              input.friendly_name,
            ),
          );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/auth/passkeys/registration/verify",
    authenticateCustomer,
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const input = z
          .object({
            challenge_id: z.string().uuid(),
            credential: registrationCredential,
          })
          .strict()
          .parse(request.body);
        const identity = request.authenticatedCustomer;
        if (!identity)
          throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
        response.status(201).json(
          await service.verifyRegistration({
            tenantId: identity.tenantId,
            scope: "TENANT",
            challengeId: input.challenge_id,
            credential: input.credential as RegistrationResponseJSON,
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/auth/passkeys/authentication/options",
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const input = z
          .object({ identifier: z.string().min(3).max(254).optional() })
          .strict()
          .parse(request.body);
        response.status(200).json(
          await service.createAuthenticationOptions({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            scope: "TENANT",
            ...(input.identifier ? { identifier: input.identifier } : {}),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/auth/passkeys/authentication/verify",
    async (request, response, next) => {
      try {
        const input = z
          .object({
            challenge_id: z.string().uuid(),
            credential: authenticationCredential,
            device_id: z.string().uuid().optional(),
          })
          .strict()
          .parse(request.body);
        response.status(200).json(
          await service.verifyAuthentication({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            scope: "TENANT",
            challengeId: input.challenge_id,
            credential: input.credential as AuthenticationResponseJSON,
            idempotencyKey: header(request, "idempotency-key"),
            ...(input.device_id ? { deviceId: input.device_id } : {}),
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-passkeys/registration/options",
    administratorAccess,
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const input = scopeSchema
          .and(
            z.object({
              administrator_id: z.string().uuid(),
              user_name: z.string().min(1).max(254),
              display_name: z.string().min(1).max(200),
              authorization_version: z.number().int().positive(),
              friendly_name: z.string().min(1).max(150).optional(),
            }),
          )
          .parse(request.body);
        response.status(200).json(
          await service.createRegistrationOptions(
            {
              tenantId: input.tenant_id,
              subjectId: input.administrator_id,
              subjectType: "ADMINISTRATOR",
              scope: input.scope,
              userName: input.user_name,
              displayName: input.display_name,
              authorizationVersion: input.authorization_version,
            },
            input.friendly_name,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-passkeys/registration/verify",
    administratorAccess,
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const input = scopeSchema
          .and(
            z.object({
              challenge_id: z.string().uuid(),
              credential: registrationCredential,
            }),
          )
          .parse(request.body);
        response.status(201).json(
          await service.verifyRegistration({
            tenantId: input.tenant_id,
            scope: input.scope,
            challengeId: input.challenge_id,
            credential: input.credential as RegistrationResponseJSON,
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/administrator-passkeys/authentication/verify",
    administratorAccess,
    async (request, response, next) => {
      try {
        const input = scopeSchema
          .and(
            z.object({
              challenge_id: z.string().uuid(),
              credential: authenticationCredential,
            }),
          )
          .parse(request.body);
        response.status(200).json(
          await service.verifyAuthentication({
            tenantId: input.tenant_id,
            scope: input.scope,
            challengeId: input.challenge_id,
            credential: input.credential as AuthenticationResponseJSON,
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
