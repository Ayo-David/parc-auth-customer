import { timingSafeEqual } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { ApiError } from "./api-error.js";
import type { SessionService } from "../services/session-service.js";

const refreshSchema = z.object({ refresh_token: z.string().min(32) }).strict();
const introspectionSchema = z
  .object({ token: z.string().min(20), audience: z.string().optional() })
  .strict();

function header(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}

function serviceAuthorized(
  authorization: string | undefined,
  expectedToken: string,
): boolean {
  const supplied = authorization?.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";
  const suppliedBuffer = Buffer.from(supplied);
  const expectedBuffer = Buffer.from(expectedToken);
  return (
    suppliedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(suppliedBuffer, expectedBuffer)
  );
}

export function createSessionRouter(
  sessions: SessionService,
  authenticate: RequestHandler,
  internalServiceToken: string,
): Router {
  const router = Router();
  router.post("/v1/auth/token/refresh", async (request, response, next) => {
    try {
      header(request, "idempotency-key");
      const scope =
        request.header("x-auth-scope") === "PLATFORM" ? "PLATFORM" : "TENANT";
      const tenantHeader = request.header("x-tenant-id");
      const tenantId =
        scope === "PLATFORM" ? null : z.string().uuid().parse(tenantHeader);
      const input = refreshSchema.parse(request.body);
      response
        .status(200)
        .json(await sessions.refresh(tenantId, input.refresh_token, scope));
    } catch (error) {
      next(error);
    }
  });
  router.post(
    "/v1/auth/logout",
    authenticate,
    async (request, response, next) => {
      try {
        header(request, "idempotency-key");
        const identity = request.authenticatedCustomer;
        if (!identity?.sessionId)
          throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
        await sessions.logout(identity.tenantId, identity.sessionId);
        response.status(204).send();
      } catch (error) {
        next(error);
      }
    },
  );
  router.post(
    "/internal/v1/tokens/introspect",
    async (request, response, next) => {
      try {
        if (
          !serviceAuthorized(
            request.header("authorization"),
            internalServiceToken,
          )
        )
          throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
        const input = introspectionSchema.parse(request.body);
        response
          .status(200)
          .json(await sessions.introspect(input.token, input.audience));
      } catch (error) {
        next(error);
      }
    },
  );
  return router;
}
