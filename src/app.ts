import { randomUUID } from "node:crypto";
import express, { type Express, type RequestHandler } from "express";
import helmet from "helmet";
import { pinoHttp } from "pino-http";
import type { Logger } from "pino";
import { ZodError } from "zod";
import type { AppConfig } from "./config/env.js";
import { checkReadiness, type ReadinessCheck } from "./health/readiness.js";
import { ApiError } from "./http/api-error.js";
import { createCustomerRouter } from "./http/customer-router.js";
import { createAuthenticationRouter } from "./http/authentication-router.js";
import { createSessionRouter } from "./http/session-router.js";
import {
  customerAuthentication,
  type AccessTokenVerifier,
} from "./security/access-token-verifier.js";
import type { CustomerService } from "./services/customer-service.js";
import type { AuthenticationService } from "./services/authentication-service.js";
import type { OtpService } from "./services/otp-service.js";
import type { SessionService } from "./services/session-service.js";
import type { AdministratorAuthenticationService } from "./services/administrator-authentication-service.js";
import { createAdministratorAuthenticationRouter } from "./http/administrator-authentication-router.js";
import type { CustomerMfaService } from "./services/customer-mfa-service.js";
import type { PasskeyService } from "./services/passkey-service.js";
import { createPasskeyRouter } from "./http/passkey-router.js";
import type { KycService } from "./services/kyc-service.js";
import { createKycRouter } from "./http/kyc-router.js";
import { createTransactionAuthorizationRouter } from "./http/transaction-authorization-router.js";
import type { TransactionAuthorizationService } from "./services/transaction-authorization-service.js";
import type { CustomerExperienceService } from "./services/customer-experience-service.js";
import { createCustomerExperienceRouter } from "./http/customer-experience-router.js";

export interface AppDependencies {
  config: AppConfig;
  logger: Logger;
  readinessChecks?: readonly ReadinessCheck[];
  customerService?: CustomerService;
  accessTokenVerifier?: AccessTokenVerifier;
  authenticationService?: AuthenticationService;
  otpService?: OtpService;
  sessionService?: SessionService;
  administratorAuthenticationService?: AdministratorAuthenticationService;
  customerMfaService?: CustomerMfaService;
  passkeyService?: PasskeyService;
  kycService?: KycService;
  transactionAuthorizationService?: TransactionAuthorizationService;
  customerExperienceService?: CustomerExperienceService;
  jwks?: { keys: object[] };
}

export function createApp({
  config,
  logger,
  readinessChecks = [],
  customerService,
  accessTokenVerifier,
  authenticationService,
  otpService,
  sessionService,
  administratorAuthenticationService,
  customerMfaService,
  passkeyService,
  kycService,
  transactionAuthorizationService,
  customerExperienceService,
  jwks,
}: AppDependencies): Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "256kb" }));
  app.use(
    pinoHttp({
      logger,
      genReqId(request, response) {
        const supplied = request.headers["x-request-id"];
        const requestId =
          typeof supplied === "string" && supplied.length <= 150
            ? supplied
            : randomUUID();
        response.setHeader("x-request-id", requestId);
        return requestId;
      },
    }) as RequestHandler,
  );

  app.get("/health", (_request, response) => {
    response.status(200).json({
      status: "UP",
      service: config.SERVICE_NAME,
      version: config.SERVICE_VERSION,
    });
  });

  app.get("/ready", async (_request, response, next) => {
    try {
      const result = await checkReadiness(readinessChecks);
      response
        .status(result.ready ? 200 : 503)
        .json({ status: result.ready ? "UP" : "DOWN", ...result });
    } catch (error) {
      next(error);
    }
  });

  if (jwks)
    app.get("/.well-known/jwks.json", (_request, response) => {
      response.setHeader("cache-control", "public, max-age=300");
      response.status(200).json(jwks);
    });

  if (customerService && accessTokenVerifier)
    app.use(
      createCustomerRouter(
        customerService,
        customerAuthentication(accessTokenVerifier),
      ),
    );
  if (authenticationService && accessTokenVerifier)
    app.use(
      createAuthenticationRouter(
        authenticationService,
        customerAuthentication(accessTokenVerifier),
        otpService,
        customerMfaService,
      ),
    );
  if (sessionService && accessTokenVerifier)
    app.use(
      createSessionRouter(
        sessionService,
        customerAuthentication(accessTokenVerifier),
        config.INTERNAL_SERVICE_TOKEN,
      ),
    );
  if (administratorAuthenticationService)
    app.use(
      createAdministratorAuthenticationRouter(
        administratorAuthenticationService,
        config.INTERNAL_SERVICE_TOKEN,
      ),
    );
  if (passkeyService && accessTokenVerifier)
    app.use(
      createPasskeyRouter(
        passkeyService,
        customerAuthentication(accessTokenVerifier),
        config.INTERNAL_SERVICE_TOKEN,
      ),
    );
  if (kycService && accessTokenVerifier)
    app.use(
      createKycRouter(kycService, customerAuthentication(accessTokenVerifier)),
    );
  if (transactionAuthorizationService && accessTokenVerifier)
    app.use(
      createTransactionAuthorizationRouter(
        transactionAuthorizationService,
        customerAuthentication(accessTokenVerifier),
        config.INTERNAL_SERVICE_TOKEN,
      ),
    );
  if (customerExperienceService && accessTokenVerifier)
    app.use(
      createCustomerExperienceRouter(
        customerExperienceService,
        customerAuthentication(accessTokenVerifier),
      ),
    );

  app.use((_request, response) => {
    response
      .status(404)
      .json({ code: "NOT_FOUND", message: "Resource not found" });
  });

  app.use(((error: unknown, request, response, _next) => {
    if (error instanceof ZodError) {
      response.status(400).json({
        code: "INVALID_REQUEST",
        message: "Request validation failed",
        details: error.flatten(),
      });
      return;
    }
    if (error instanceof ApiError) {
      response.status(error.status).json({
        code: error.code,
        message: error.message,
        ...(error.details === undefined ? {} : { details: error.details }),
      });
      return;
    }
    request.log.error({ err: error }, "Unhandled request error");
    response.status(500).json({
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred",
    });
  }) as express.ErrorRequestHandler);

  return app;
}
