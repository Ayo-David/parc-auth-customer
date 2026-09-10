import { randomUUID } from "node:crypto";
import { Router, type RequestHandler } from "express";
import { z } from "zod";
import { ApiError } from "./api-error.js";
import type { CustomerService } from "../services/customer-service.js";
import type { AuthenticatedCustomer } from "../security/access-token-verifier.js";

const headersSchema = z.object({
  tenantId: z.string().uuid(),
  idempotencyKey: z.string().min(1).max(255),
});

const registrationSchema = z
  .object({
    phone_number: z.string().regex(/^\+234[789][01][0-9]{8}$/),
    email: z.string().email().optional(),
    password: z.string().min(12).max(128),
    consent_ids: z.array(z.string().uuid()).min(1),
  })
  .strict()
  .superRefine(({ consent_ids }, context) => {
    if (new Set(consent_ids).size !== consent_ids.length)
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["consent_ids"],
        message: "Consent identifiers must be unique",
      });
  });

const profileUpdateSchema = z
  .object({
    first_name: z.string().trim().min(1).max(100).optional(),
    last_name: z.string().trim().min(1).max(100).optional(),
    email: z.string().email().optional(),
  })
  .strict()
  .refine(
    (input) => Object.values(input).some((value) => value !== undefined),
    {
      message: "At least one profile field is required",
    },
  );

function requiredHeader(
  request: { header(name: string): string | undefined },
  name: string,
): string {
  const value = request.header(name);
  if (!value) throw new ApiError(400, "INVALID_REQUEST", `${name} is required`);
  return value;
}

function requiredIdentity(
  identity?: AuthenticatedCustomer,
): AuthenticatedCustomer {
  if (!identity)
    throw new ApiError(401, "UNAUTHORIZED", "Authentication required");
  return identity;
}

export function createCustomerRouter(
  customers: CustomerService,
  authenticate: RequestHandler,
): Router {
  const router = Router();

  router.post("/v1/customers/register", async (request, response, next) => {
    try {
      const headers = headersSchema.parse({
        tenantId: requiredHeader(request, "x-tenant-id"),
        idempotencyKey: requiredHeader(request, "idempotency-key"),
      });
      const input = registrationSchema.parse(request.body);
      const correlationHeader = request.header("x-correlation-id");
      const parsedCorrelation = z.string().uuid().safeParse(correlationHeader);
      const correlationId = parsedCorrelation.success
        ? parsedCorrelation.data
        : randomUUID();
      const userAgent = request.header("user-agent");
      const customer = await customers.register({
        tenantId: headers.tenantId,
        idempotencyKey: headers.idempotencyKey,
        correlationId,
        phoneNumber: input.phone_number,
        ...(input.email ? { email: input.email } : {}),
        password: input.password,
        consentIds: input.consent_ids,
        ...(request.ip ? { ipAddress: request.ip } : {}),
        ...(userAgent ? { userAgent } : {}),
      });
      response.status(201).json(customer);
    } catch (error) {
      next(error);
    }
  });

  router.get(
    "/v1/customers/me",
    authenticate,
    async (request, response, next) => {
      try {
        const identity = requiredIdentity(request.authenticatedCustomer);
        response
          .status(200)
          .json(await customers.get(identity.tenantId, identity.subject));
      } catch (error) {
        next(error);
      }
    },
  );

  router.patch(
    "/v1/customers/me",
    authenticate,
    async (request, response, next) => {
      try {
        const idempotencyKey = requiredHeader(request, "idempotency-key");
        const identity = requiredIdentity(request.authenticatedCustomer);
        const input = profileUpdateSchema.parse(request.body);
        response.status(200).json(
          await customers.update(
            identity.tenantId,
            identity.subject,
            idempotencyKey,
            {
              ...(input.first_name !== undefined
                ? { firstName: input.first_name }
                : {}),
              ...(input.last_name !== undefined
                ? { lastName: input.last_name }
                : {}),
              ...(input.email !== undefined ? { email: input.email } : {}),
            },
          ),
        );
      } catch (error) {
        next(error);
      }
    },
  );

  return router;
}
