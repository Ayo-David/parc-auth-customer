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
  const resolve = async (customer?: AuthenticatedCustomer) => {
    const identity = required(customer);
    return {
      tenantId: identity.tenantId,
      userId: await service.userIdForCustomer(
        identity.tenantId,
        identity.subject,
      ),
    };
  };
  router.use("/v1/security", authenticate);
  router.use("/v1/notifications", authenticate);
  router.use("/v1/notification-preferences", authenticate);
  router.use("/v1/devices", authenticate);
  router.use("/v1/referrals/summary", authenticate);
  router.get("/v1/security", async (request, response, next) => {
    try {
      const identity = await resolve(request.authenticatedCustomer);
      response.json(await service.security(identity.tenantId, identity.userId));
    } catch (error) {
      next(error);
    }
  });
  router.get("/v1/notifications", async (request, response, next) => {
    try {
      const identity = await resolve(request.authenticatedCustomer);
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
          identity.userId,
          pageSize,
        ),
      );
    } catch (error) {
      next(error);
    }
  });
  router.get(
    "/v1/notification-preferences",
    async (request, response, next) => {
      try {
        const identity = await resolve(request.authenticatedCustomer);
        response.json(
          await service.notificationPreferences(
            identity.tenantId,
            identity.userId,
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put(
    "/v1/notification-preferences/:category",
    async (request, response, next) => {
      try {
        requiredHeader(request, "idempotency-key");
        const identity = await resolve(request.authenticatedCustomer);
        const category = z
          .string()
          .regex(/^[A-Z][A-Z0-9_]{1,99}$/)
          .parse(request.params.category);
        const body = z
          .object({
            push_enabled: z.boolean(),
            sms_enabled: z.boolean(),
            email_enabled: z.boolean(),
            in_app_enabled: z.boolean(),
          })
          .strict()
          .parse(request.body);
        response.json(
          await service.updateNotificationPreference({
            tenantId: identity.tenantId,
            userId: identity.userId,
            category,
            pushEnabled: body.push_enabled,
            smsEnabled: body.sms_enabled,
            emailEnabled: body.email_enabled,
            inAppEnabled: body.in_app_enabled,
          }),
        );
      } catch (error) {
        next(error);
      }
    },
  );
  router.put("/v1/devices/push-token", async (request, response, next) => {
    try {
      requiredHeader(request, "idempotency-key");
      const identity = await resolve(request.authenticatedCustomer);
      const body = z
        .object({
          device_identifier: z.string().min(1).max(255),
          push_token: z.string().min(20).max(4096),
          platform: z.enum(["ANDROID", "IOS"]),
          device_name: z.string().max(150).optional(),
          os_version: z.string().max(50).optional(),
          app_version: z.string().max(50).optional(),
        })
        .strict()
        .parse(request.body);
      response.json(
        await service.registerPushDevice({
          tenantId: identity.tenantId,
          userId: identity.userId,
          deviceIdentifier: body.device_identifier,
          pushToken: body.push_token,
          platform: body.platform,
          ...(body.device_name ? { deviceName: body.device_name } : {}),
          ...(body.os_version ? { osVersion: body.os_version } : {}),
          ...(body.app_version ? { appVersion: body.app_version } : {}),
        }),
      );
    } catch (error) {
      next(error);
    }
  });
  router.delete("/v1/devices/:id", async (request, response, next) => {
    try {
      requiredHeader(request, "idempotency-key");
      const identity = await resolve(request.authenticatedCustomer);
      await service.revokeDevice(
        identity.tenantId,
        identity.userId,
        z.string().uuid().parse(request.params.id),
      );
      response.status(204).send();
    } catch (error) {
      next(error);
    }
  });
  router.delete(
    "/v1/security/sessions/:id",
    async (request, response, next) => {
      try {
        requiredHeader(request, "idempotency-key");
        const identity = await resolve(request.authenticatedCustomer);
        await service.revokeSession(
          identity.tenantId,
          identity.userId,
          z.string().uuid().parse(request.params.id),
        );
        response.status(204).send();
      } catch (error) {
        next(error);
      }
    },
  );
  router.get("/v1/referrals/summary", async (request, response, next) => {
    try {
      const identity = await resolve(request.authenticatedCustomer);
      response.json(
        await service.referralSummary(identity.tenantId, identity.userId),
      );
    } catch (error) {
      next(error);
    }
  });
  return router;
}
function requiredHeader(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}
function required(identity?: AuthenticatedCustomer): AuthenticatedCustomer {
  if (!identity)
    throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
  return identity;
}
