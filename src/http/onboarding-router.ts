import { randomUUID } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";
import type { KycService } from "../services/kyc-service.js";
import type { OnboardingService } from "../services/onboarding-service.js";
import type { OtpService } from "../services/otp-service.js";
import { ApiError } from "./api-error.js";

const phone = z.string().regex(/^\+234[789][01][0-9]{8}$/);
const idempotency = (request: { header(name: string): string | undefined }) =>
  required(request, "idempotency-key");
const tenant = (request: { header(name: string): string | undefined }) =>
  z.string().uuid().parse(required(request, "x-tenant-id"));
function required(
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

export function createOnboardingRouter(
  onboarding: OnboardingService,
  otp: OtpService,
  kyc: KycService,
  authenticate: RequestHandler,
): Router {
  const router = Router();
  const resolve = async (customer?: AuthenticatedCustomer) => {
    const subject = identity(customer);
    return {
      tenantId: subject.tenantId,
      userId: await onboarding.userIdForCustomer(
        subject.tenantId,
        subject.subject,
      ),
    };
  };
  router.post(
    "/v1/onboarding/registrations",
    async (request, response, next) => {
      try {
        const input = z
          .object({
            phone_number: phone,
            consent_ids: z.array(z.string().uuid()).min(1),
            referral_code: z.string().min(3).max(30).optional(),
          })
          .strict()
          .parse(request.body);
        const tenantId = tenant(request);
        const key = idempotency(request);
        const userAgent = request.header("user-agent");
        const registration = await onboarding.start({
          tenantId,
          idempotencyKey: key,
          phoneNumber: input.phone_number,
          consentIds: input.consent_ids,
          ...(input.referral_code ? { referralCode: input.referral_code } : {}),
          ...(request.ip ? { ipAddress: request.ip } : {}),
          ...(userAgent ? { userAgent } : {}),
        });
        const challenge = await otp.request({
          tenantId,
          idempotencyKey: `${key}:phone-otp`,
          purpose: "PHONE_VERIFICATION",
          channel: "SMS",
          destination: input.phone_number,
        });
        response
          .status(201)
          .json({ ...registration, phone_challenge: challenge });
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/phone/verify",
    async (request, response, next) => {
      try {
        const input = z
          .object({
            onboarding_id: z.string().uuid(),
            challenge_id: z.string().uuid(),
            code: z.string().regex(/^[0-9]{6}$/),
          })
          .strict()
          .parse(request.body);
        const tenantId = tenant(request);
        const tokens = await otp.verify({
          tenantId,
          idempotencyKey: idempotency(request),
          challengeId: input.challenge_id,
          code: input.code,
        });
        const onboardingState = await onboarding.markPhoneVerifiedBySession(
          tenantId,
          input.onboarding_id,
        );
        response.json({ tokens, onboarding: onboardingState });
      } catch (error) {
        next(error);
      }
    },
  );
  router.get(
    "/v1/onboarding/status",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        response.json(
          await onboarding.status(subject.tenantId, subject.userId),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/onboarding/email",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            email: z.string().email().optional(),
            skip: z.boolean().optional(),
          })
          .strict()
          .refine((v) => Boolean(v.email) !== Boolean(v.skip))
          .parse(request.body);
        const state = await onboarding.updateEmail(
          subject.tenantId,
          subject.userId,
          input.email?.toLowerCase(),
        );
        const challenge = input.email
          ? await otp.request({
              tenantId: subject.tenantId,
              idempotencyKey: `${idempotency(request)}:email-otp`,
              purpose: "EMAIL_VERIFICATION",
              channel: "EMAIL",
              destination: input.email,
            })
          : undefined;
        response.json({
          onboarding: state,
          ...(challenge ? { email_challenge: challenge } : {}),
        });
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/email/verify",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            challenge_id: z.string().uuid(),
            code: z.string().regex(/^[0-9]{6}$/),
          })
          .strict()
          .parse(request.body);
        await otp.verify({
          tenantId: subject.tenantId,
          idempotencyKey: idempotency(request),
          challengeId: input.challenge_id,
          code: input.code,
        });
        response.json(
          await onboarding.markEmailVerified(subject.tenantId, subject.userId),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/identity",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            identity_type: z.literal("NIN"),
            identity_value: z.string().regex(/^[0-9]{11}$/),
            consent_id: z.string().uuid(),
          })
          .strict()
          .parse(request.body);
        const result = await kyc.start({
          tenantId: subject.tenantId,
          userId: subject.userId,
          identityType: input.identity_type,
          identityValue: input.identity_value,
          consentId: input.consent_id,
          idempotencyKey: idempotency(request),
          correlationId: z
            .string()
            .uuid()
            .catch(randomUUID())
            .parse(request.header("x-correlation-id")),
        });
        const state =
          result.status === "VERIFIED"
            ? await onboarding.markIdentity(
                subject.tenantId,
                subject.userId,
                true,
              )
            : await onboarding.status(subject.tenantId, subject.userId);
        response.status(202).json({ verification: result, onboarding: state });
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/face-verification",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            identity_type: z.literal("NIN"),
            identity_value: z.string().regex(/^[0-9]{11}$/),
            liveness_reference: z.string().min(1).max(255),
            consent_id: z.string().uuid(),
          })
          .strict()
          .parse(request.body);
        const result = await kyc.startBiometric({
          tenantId: subject.tenantId,
          userId: subject.userId,
          identityType: input.identity_type,
          identityValue: input.identity_value,
          livenessReference: input.liveness_reference,
          consentId: input.consent_id,
          idempotencyKey: idempotency(request),
          correlationId: z
            .string()
            .uuid()
            .catch(randomUUID())
            .parse(request.header("x-correlation-id")),
        });
        const state =
          result.status === "VERIFIED"
            ? await onboarding.markFaceVerified(
                subject.tenantId,
                subject.userId,
              )
            : await onboarding.status(subject.tenantId, subject.userId);
        response.status(202).json({ verification: result, onboarding: state });
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/face-verification/confirm",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({ verification_id: z.string().uuid() })
          .strict()
          .parse(request.body);
        response.json(
          await onboarding.confirmFaceVerification(
            subject.tenantId,
            subject.userId,
            input.verification_id,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/onboarding/address",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            state: z.string().min(2).max(100),
            lga: z.string().min(2).max(100),
            area: z.string().min(1).max(150),
            street_address: z.string().min(3).max(255),
            landmark: z.string().max(255).optional(),
          })
          .strict()
          .parse(request.body);
        response.json(
          await onboarding.updateAddress(
            subject.tenantId,
            subject.userId,
            input,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/onboarding/compliance",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({ politically_exposed_person: z.boolean() })
          .strict()
          .parse(request.body);
        response.json(
          await onboarding.updateCompliance(
            subject.tenantId,
            subject.userId,
            input.politically_exposed_person,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/onboarding/income",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            occupation: z.string().min(2).max(150),
            annual_income_band: z.string().min(1).max(80),
            has_other_income: z.boolean(),
          })
          .strict()
          .parse(request.body);
        response.json(
          await onboarding.updateIncome(subject.tenantId, subject.userId, {
            occupation: input.occupation,
            annualIncomeBand: input.annual_income_band,
            hasOtherIncome: input.has_other_income,
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/onboarding/login-passcode",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({
            passcode: z.string().regex(/^[0-9]{6}$/),
            passcode_confirmation: z.string().regex(/^[0-9]{6}$/),
          })
          .strict()
          .refine((v) => v.passcode === v.passcode_confirmation, {
            path: ["passcode_confirmation"],
            message: "Passcodes must match",
          })
          .parse(request.body);
        response.json(
          await onboarding.setLoginPasscode(
            subject.tenantId,
            subject.userId,
            input.passcode,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/v1/onboarding/complete",
    authenticate,
    async (request, response, next) => {
      try {
        const subject = await resolve(request.authenticatedCustomer);
        const input = z
          .object({ biometric_enrolled: z.boolean() })
          .strict()
          .parse(request.body);
        response.json(
          await onboarding.completeBiometric(
            subject.tenantId,
            subject.userId,
            input.biometric_enrolled,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
