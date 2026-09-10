import { createHmac, randomUUID } from "node:crypto";
import type { Knex } from "knex";
import argon2 from "argon2";
import { ApiError } from "../http/api-error.js";
import { withTenantTransaction } from "../database/transaction.js";
import { ConsentRepository } from "../repositories/consent-repository.js";
import {
  CustomerRepository,
  type CustomerProfileRecord,
} from "../repositories/customer-repository.js";
import { CredentialRepository } from "../repositories/credential-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import { IdempotencyRepository } from "../repositories/idempotency-repository.js";
import type { UserRecord } from "../repositories/types.js";
import { UserRepository } from "../repositories/user-repository.js";
import type { TenantAdminClient } from "./tenant-admin-client.js";

export interface CustomerView {
  id: string;
  tenant_id: string;
  status: "PENDING_VERIFICATION" | "ACTIVE" | "RESTRICTED" | "CLOSED";
  first_name?: string;
  last_name?: string;
  masked_phone_number?: string;
  masked_email?: string;
  created_at: string;
}

export interface RegisterCustomerInput {
  tenantId: string;
  idempotencyKey: string;
  correlationId: string;
  phoneNumber: string;
  email?: string;
  password: string;
  consentIds: readonly string[];
  ipAddress?: string;
  userAgent?: string;
}

function customerStatus(status: UserRecord["status"]): CustomerView["status"] {
  if (status === "PENDING") return "PENDING_VERIFICATION";
  if (status === "ACTIVE") return "ACTIVE";
  if (status === "DEACTIVATED") return "CLOSED";
  return "RESTRICTED";
}

function maskPhone(phone: string): string {
  return `${phone.slice(0, 4)}******${phone.slice(-3)}`;
}

function maskEmail(email: string): string {
  const [local = "", domain = ""] = email.split("@");
  return `${local.slice(0, 1)}***@${domain}`;
}

function toView(
  user: UserRecord,
  profile: CustomerProfileRecord,
): CustomerView {
  return {
    id: profile.id,
    tenant_id: user.tenant_id,
    status: customerStatus(user.status),
    ...(profile.first_name ? { first_name: profile.first_name } : {}),
    ...(profile.last_name ? { last_name: profile.last_name } : {}),
    ...(user.phone ? { masked_phone_number: maskPhone(user.phone) } : {}),
    ...(user.email ? { masked_email: maskEmail(user.email) } : {}),
    created_at: profile.created_at.toISOString(),
  };
}

export class CustomerService {
  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: TenantAdminClient,
    private readonly idempotencySecret: string,
  ) {}

  public async register(input: RegisterCustomerInput): Promise<CustomerView> {
    const phone = input.phoneNumber.trim();
    const email = input.email?.trim().toLowerCase();
    const documents = await this.tenantAdmin.validateRegistration(
      input.tenantId,
      input.consentIds,
      input.idempotencyKey,
    );
    const requestHash = createHmac("sha256", this.idempotencySecret)
      .update(
        JSON.stringify({
          phone,
          email: email ?? null,
          password: input.password,
          consentIds: [...input.consentIds].sort(),
        }),
      )
      .digest("hex");
    const passwordHash = await argon2.hash(input.password, {
      type: argon2.argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1,
    });

    try {
      return await withTenantTransaction(
        this.database,
        input.tenantId,
        async (transaction) => {
          const idempotency = new IdempotencyRepository(transaction);
          const claim = await idempotency.claim({
            tenantId: input.tenantId,
            key: input.idempotencyKey,
            operation: "customer.register",
            requestHash,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          });
          if (!claim.created) {
            if (claim.record.status === "COMPLETED")
              return claim.record.response_body as CustomerView;
            throw new ApiError(
              409,
              "REQUEST_IN_PROGRESS",
              "An equivalent registration request is in progress",
            );
          }

          const user = await new UserRepository(transaction).create({
            tenantId: input.tenantId,
            phone,
            phoneNormalized: phone,
            ...(email ? { email, emailNormalized: email } : {}),
          });
          const profile = await new CustomerRepository(transaction).create({
            tenantId: input.tenantId,
            userId: user.id,
            customerNumber: `CUS-${randomUUID().replaceAll("-", "").toUpperCase()}`,
          });
          await new CredentialRepository(transaction).create({
            tenantId: input.tenantId,
            userId: user.id,
            type: "PASSWORD",
            hash: passwordHash,
          });
          await new ConsentRepository(transaction).grantAll({
            tenantId: input.tenantId,
            userId: user.id,
            documents,
            ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
            ...(input.userAgent ? { userAgent: input.userAgent } : {}),
          });
          const response = toView(user, profile);
          const eventId = randomUUID();
          await new EventRepository(transaction).publish({
            tenantId: input.tenantId,
            eventId,
            eventType: "customer.registered.v1",
            aggregateType: "customer",
            aggregateId: profile.id,
            payload: {
              event_id: eventId,
              event_type: "customer.registered.v1",
              event_version: 1,
              occurred_at: new Date().toISOString(),
              producer: "parc-auth-customer",
              tenant_id: input.tenantId,
              aggregate_type: "customer",
              aggregate_id: profile.id,
              aggregate_version: 1,
              correlation_id: input.correlationId,
              causation_id: null,
              idempotency_key: input.idempotencyKey,
              data_classification: "CONFIDENTIAL",
              payload: {
                customer_id: profile.id,
                user_id: user.id,
                status: "PENDING_VERIFICATION",
              },
            },
          });
          await idempotency.complete({
            tenantId: input.tenantId,
            key: input.idempotencyKey,
            operation: "customer.register",
            responseCode: 201,
            responseBody: response,
          });
          return response;
        },
      );
    } catch (error) {
      if ((error as { code?: string }).code === "23505")
        throw new ApiError(
          409,
          "CUSTOMER_ALREADY_EXISTS",
          "A customer with these details already exists",
        );
      if (
        error instanceof Error &&
        error.message === "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"
      )
        throw new ApiError(
          409,
          "IDEMPOTENCY_CONFLICT",
          "Idempotency key was used with a different request",
        );
      throw error;
    }
  }

  public get(tenantId: string, userId: string): Promise<CustomerView> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        const user = await new UserRepository(transaction).findById(userId);
        const profile = await new CustomerRepository(transaction).findByUserId(
          userId,
        );
        if (!user || !profile)
          throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
        return toView(user, profile);
      },
    );
  }

  public update(
    tenantId: string,
    userId: string,
    idempotencyKey: string,
    input: { firstName?: string; lastName?: string; email?: string },
  ): Promise<CustomerView> {
    const normalized = {
      ...(input.firstName !== undefined
        ? { firstName: input.firstName.trim() }
        : {}),
      ...(input.lastName !== undefined
        ? { lastName: input.lastName.trim() }
        : {}),
      ...(input.email !== undefined
        ? { email: input.email.trim().toLowerCase() }
        : {}),
    };
    const requestHash = createHmac("sha256", this.idempotencySecret)
      .update(JSON.stringify({ userId, ...normalized }))
      .digest("hex");
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        const idempotency = new IdempotencyRepository(transaction);
        const claim = await idempotency.claim({
          tenantId,
          key: idempotencyKey,
          operation: "customer.profile.update",
          requestHash,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        if (!claim.created) {
          if (claim.record.status === "COMPLETED")
            return claim.record.response_body as CustomerView;
          throw new ApiError(
            409,
            "REQUEST_IN_PROGRESS",
            "An equivalent profile update is in progress",
          );
        }
        const users = new UserRepository(transaction);
        let user = await users.findById(userId);
        if (!user)
          throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
        if (normalized.email !== undefined)
          user = await users.updateEmail({
            id: userId,
            email: normalized.email,
            emailNormalized: normalized.email,
          });
        const profile = await new CustomerRepository(transaction).update(
          userId,
          normalized,
        );
        const response = toView(user, profile);
        await idempotency.complete({
          tenantId,
          key: idempotencyKey,
          operation: "customer.profile.update",
          responseCode: 200,
          responseBody: response,
        });
        return response;
      },
    ).catch((error: unknown) => {
      if ((error as { code?: string }).code === "23505")
        throw new ApiError(
          409,
          "EMAIL_ALREADY_EXISTS",
          "Email address is already in use",
        );
      if (
        error instanceof Error &&
        error.message === "IDEMPOTENCY_KEY_REUSED_WITH_DIFFERENT_REQUEST"
      )
        throw new ApiError(
          409,
          "IDEMPOTENCY_CONFLICT",
          "Idempotency key was used with a different request",
        );
      throw error;
    });
  }
}
