import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { ApiError } from "./api-error.js";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";
import type { AuthenticationService } from "../services/authentication-service.js";
import type { OtpService } from "../services/otp-service.js";
import type { CustomerMfaService } from "../services/customer-mfa-service.js";

const loginSchema = z
  .object({
    identifier: z.string().min(3).max(254),
    password: z.string().min(1).max(128),
    device_id: z.string().uuid(),
  })
  .strict();
const passcodeLoginSchema = z
  .object({
    identifier: z.string().min(3).max(254),
    passcode: z.string().regex(/^[0-9]{6}$/),
    device_id: z.string().uuid(),
  })
  .strict();
const pinSchema = z.object({ pin: z.string().regex(/^[0-9]{4,6}$/) }).strict();
const confirmSchema = z
  .object({
    challenge_id: z.string().uuid(),
    pin: z.string().regex(/^[0-9]{4}$/),
  })
  .strict();
const rotateSchema = z
  .object({
    current_pin: z.string().regex(/^[0-9]{4}$/),
    new_pin: z.string().regex(/^[0-9]{4}$/),
  })
  .strict();
const otpRequestSchema = z
  .object({
    purpose: z.enum([
      "LOGIN",
      "PHONE_VERIFICATION",
      "EMAIL_VERIFICATION",
      "PASSWORD_RESET",
      "STEP_UP",
    ]),
    channel: z.enum(["SMS", "EMAIL"]),
    destination: z.string().min(3).max(254),
  })
  .strict();
const otpVerifySchema = z
  .object({
    challenge_id: z.string().uuid(),
    code: z.string().regex(/^[0-9]{6}$/),
  })
  .strict();
const passcodeRecoveryRequestSchema = z
  .object({
    identifier: z.string().min(3).max(254),
    channel: z.enum(["SMS", "EMAIL"]),
  })
  .strict();
const passcodeRecoveryConfirmSchema = z
  .object({
    challenge_id: z.string().uuid(),
    code: z.string().regex(/^[0-9]{6}$/),
    new_passcode: z.string().regex(/^[0-9]{6}$/),
    new_passcode_confirmation: z.string().regex(/^[0-9]{6}$/),
  })
  .strict()
  .refine((value) => value.new_passcode === value.new_passcode_confirmation, {
    path: ["new_passcode_confirmation"],
    message: "Passcode confirmation must match",
  });

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

export function createAuthenticationRouter(
  authentication: AuthenticationService,
  authenticate: RequestHandler,
  otp?: OtpService,
  customerMfa?: CustomerMfaService,
): Router {
  const router = Router();
  router.post("/v1/auth/password/login", async (request, response, next) => {
    try {
      const input = loginSchema.parse(request.body);
      const userAgent = request.header("user-agent");
      response.status(200).json(
        await authentication.login({
          tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
          idempotencyKey: header(request, "idempotency-key"),
          identifier: input.identifier,
          password: input.password,
          deviceId: input.device_id,
          ...(request.ip ? { ipAddress: request.ip } : {}),
          ...(userAgent ? { userAgent } : {}),
        }),
      );
    } catch (error) {
      next(error);
    }
  });
  router.post("/v1/auth/passcode/login", async (request, response, next) => {
    try {
      const input = passcodeLoginSchema.parse(request.body);
      response.status(200).json(
        await authentication.loginWithPasscode({
          tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
          idempotencyKey: header(request, "idempotency-key"),
          identifier: input.identifier,
          passcode: input.passcode,
          deviceId: input.device_id,
        }),
      );
    } catch (error) {
      next(error);
    }
  });
  if (otp) {
    router.post(
      "/v1/auth/passcode/recovery/request",
      async (request, response, next) => {
        try {
          const input = passcodeRecoveryRequestSchema.parse(request.body);
          response.status(202).json(
            await otp.request({
              tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
              idempotencyKey: header(request, "idempotency-key"),
              purpose: "PASSWORD_RESET",
              channel: input.channel,
              destination: input.identifier,
            }),
          );
        } catch (error) {
          next(error);
        }
      },
    );
    router.post(
      "/v1/auth/passcode/recovery/confirm",
      async (request, response, next) => {
        try {
          const input = passcodeRecoveryConfirmSchema.parse(request.body);
          await otp.resetLoginPasscode({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            idempotencyKey: header(request, "idempotency-key"),
            challengeId: input.challenge_id,
            code: input.code,
            newPasscode: input.new_passcode,
          });
          response.status(204).send();
        } catch (error) {
          next(error);
        }
      },
    );
    router.post("/v1/auth/otp/request", async (request, response, next) => {
      try {
        const input = otpRequestSchema.parse(request.body);
        response.status(202).json(
          await otp.request({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            idempotencyKey: header(request, "idempotency-key"),
            purpose: input.purpose,
            channel: input.channel,
            destination: input.destination,
          }),
        );
      } catch (error) {
        next(error);
      }
    });
    router.post("/v1/auth/otp/verify", async (request, response, next) => {
      try {
        const input = otpVerifySchema.parse(request.body);
        response.status(200).json(
          await otp.verify({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            idempotencyKey: header(request, "idempotency-key"),
            challengeId: input.challenge_id,
            code: input.code,
          }),
        );
      } catch (error) {
        next(error);
      }
    });
  }
  if (customerMfa)
    router.post("/v1/auth/mfa/verify", async (request, response, next) => {
      try {
        const input = z
          .object({
            challenge_id: z.string().uuid(),
            response: z.string().min(1).max(4096),
          })
          .strict()
          .parse(request.body);
        response.status(200).json(
          await customerMfa.verify({
            tenantId: z.string().uuid().parse(header(request, "x-tenant-id")),
            idempotencyKey: header(request, "idempotency-key"),
            challengeId: input.challenge_id,
            response: input.response,
          }),
        );
      } catch (error) {
        next(error);
      }
    });
  router.post(
    "/v1/security/transaction-pin/setup",
    authenticate,
    async (request, response, next) => {
      try {
        const idempotencyKey = header(request, "idempotency-key");
        const customer = identity(request.authenticatedCustomer);
        response
          .status(201)
          .json(
            await authentication.startPinSetup(
              customer.tenantId,
              customer.subject,
              idempotencyKey,
            ),
          );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/security/transaction-pin/confirm",
    authenticate,
    async (request, response, next) => {
      try {
        const idempotencyKey = header(request, "idempotency-key");
        const customer = identity(request.authenticatedCustomer);
        const input = confirmSchema.parse(request.body);
        await authentication.confirmPin(
          customer.tenantId,
          customer.subject,
          idempotencyKey,
          input.challenge_id,
          input.pin,
        );
        response.status(204).send();
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/security/transaction-pin/rotate",
    authenticate,
    async (request, response, next) => {
      try {
        const idempotencyKey = header(request, "idempotency-key");
        const customer = identity(request.authenticatedCustomer);
        const input = rotateSchema.parse(request.body);
        await authentication.rotatePin(
          customer.tenantId,
          customer.subject,
          idempotencyKey,
          input.current_pin,
          input.new_pin,
        );
        response.status(204).send();
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/auth/pin/verify",
    authenticate,
    async (request, response, next) => {
      try {
        const idempotencyKey = header(request, "idempotency-key");
        const customer = identity(request.authenticatedCustomer);
        await authentication.verifyPin(
          customer.tenantId,
          customer.subject,
          idempotencyKey,
          pinSchema.parse(request.body).pin,
        );
        response.status(204).send();
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
