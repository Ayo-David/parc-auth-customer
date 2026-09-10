import type { RequestHandler } from "express";
import { ApiError } from "../http/api-error.js";

export interface AuthenticatedCustomer {
  subject: string;
  tenantId: string;
  audience: "mobile-bff";
  sessionId?: string;
}

declare module "express-serve-static-core" {
  interface Request {
    authenticatedCustomer?: AuthenticatedCustomer;
  }
}

export interface AccessTokenVerifier {
  verify(token: string): Promise<AuthenticatedCustomer>;
}

export function customerAuthentication(
  verifier: AccessTokenVerifier,
): RequestHandler {
  return async (request, _response, next) => {
    try {
      const authorization = request.header("authorization");
      if (!authorization?.startsWith("Bearer "))
        throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
      const identity = await verifier.verify(authorization.slice(7));
      if (identity.tenantId !== request.header("x-tenant-id"))
        throw new ApiError(403, "TENANT_MISMATCH", "Tenant context mismatch");
      request.authenticatedCustomer = identity;
      next();
    } catch (error) {
      next(
        error instanceof ApiError
          ? error
          : new ApiError(401, "UNAUTHORIZED", "Authentication failed"),
      );
    }
  };
}

export class PendingJwtVerifier implements AccessTokenVerifier {
  public verify(): Promise<AuthenticatedCustomer> {
    return Promise.reject(
      new ApiError(401, "UNAUTHORIZED", "JWT verification is not configured"),
    );
  }
}
