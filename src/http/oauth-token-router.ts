import express, { Router } from "express";
import { z } from "zod";
import {
  ClientAuthenticationError,
  type ClientAssertionVerifier,
} from "../security/client-assertion-verifier.js";
import {
  OAuthError,
  type ServiceTokenService,
} from "../services/service-token-service.js";

const tokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
const scopeName = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/;
const requestSchema = z
  .object({
    grant_type: z.enum(["client_credentials", tokenExchange]),
    client_assertion_type: z.literal(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    ),
    client_assertion: z.string().min(20).max(4096),
    audience: z.string().regex(/^parc-[a-z0-9-]+$/),
    scope: z
      .string()
      .max(1024)
      .transform((value) => value.split(" "))
      .pipe(z.array(z.string().regex(scopeName)).min(1).max(20)),
    tenant_id: z.union([z.literal("platform"), z.string().uuid()]),
    subject_token: z.string().min(20).max(8192).optional(),
    subject_token_type: z
      .literal("urn:ietf:params:oauth:token-type:access_token")
      .optional(),
  })
  .strict();

/** RFC 6749 / RFC 8693 token endpoint for service-to-service access tokens. */
export function createOAuthTokenRouter(
  clients: ClientAssertionVerifier,
  tokens: ServiceTokenService,
): Router {
  const router = Router();
  router.post(
    "/internal/v1/oauth/token",
    express.urlencoded({ extended: false, limit: "16kb" }),
    async (request, response) => {
      response.setHeader("cache-control", "no-store");
      response.setHeader("pragma", "no-cache");
      try {
        const parsed = requestSchema.safeParse(request.body);
        if (!parsed.success)
          throw new OAuthError(
            400,
            "invalid_request",
            "Malformed token request",
          );
        const input = parsed.data;
        const exchange = input.grant_type === tokenExchange;
        if (exchange !== (input.subject_token !== undefined))
          throw new OAuthError(
            400,
            "invalid_request",
            "subject_token is required for token exchange only",
          );
        let client: string;
        try {
          client = await clients.verify(input.client_assertion);
        } catch (error) {
          if (error instanceof ClientAuthenticationError)
            throw new OAuthError(
              401,
              "invalid_client",
              "Client authentication failed",
            );
          throw error;
        }
        const issued = await tokens.issue({
          client,
          grant: exchange ? "token_exchange" : "client_credentials",
          audience: input.audience,
          scopes: input.scope,
          tenantId: input.tenant_id === "platform" ? null : input.tenant_id,
          ...(input.subject_token ? { subjectToken: input.subject_token } : {}),
        });
        // Never log token values; record only who received what.
        request.log.info(
          {
            client,
            audience: input.audience,
            grant: exchange ? "token_exchange" : "client_credentials",
            tenant_id: input.tenant_id,
            scope: issued.scope,
          },
          "Service access token issued",
        );
        response.status(200).json(issued);
      } catch (error) {
        if (!(error instanceof OAuthError)) {
          request.log.error({ err: error }, "Service token issuance failed");
          response.status(500).json({ error: "server_error" });
          return;
        }
        request.log.warn(
          { error: error.error, reason: error.message },
          "Service access token refused",
        );
        if (error.status === 401)
          response.setHeader(
            "WWW-Authenticate",
            'Bearer realm="parc-auth-customer"',
          );
        response
          .status(error.status)
          .json({ error: error.error, error_description: error.message });
      }
    },
  );
  return router;
}
