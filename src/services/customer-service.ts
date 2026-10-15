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
import type { IdentityNumberCipher } from "../security/identity-number-cipher.js";

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

/** What a payment provider needs to open an account in the customer's name. */
export interface CustomerProviderProfile {
  customer_id: string;
  first_name: string;
  middle_name: string | null;
  last_name: string;
  email: string;
  phone_number: string;
  /** The BVN verified at onboarding, or null if none is on file. */
  bvn: string | null;
}

export class CustomerService {
  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: TenantAdminClient,
    private readonly idempotencySecret: string,
    private readonly identityNumbers?: IdentityNumberCipher,
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

  public get(tenantId: string, customerId: string): Promise<CustomerView> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        const profile = await new CustomerRepository(transaction).findById(
          customerId,
        );
        const user = profile
          ? await new UserRepository(transaction).findById(profile.user_id)
          : undefined;
        if (!profile || !user)
          throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
        return toView(user, profile);
      },
    );
  }

  public update(
    tenantId: string,
    customerId: string,
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
      .update(JSON.stringify({ customerId, ...normalized }))
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
        const customers = new CustomerRepository(transaction);
        let profile = await customers.findById(customerId);
        let user = profile ? await users.findById(profile.user_id) : undefined;
        if (!profile || !user)
          throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
        if (normalized.email !== undefined)
          user = await users.updateEmail({
            id: profile.user_id,
            email: normalized.email,
            emailNormalized: normalized.email,
          });
        profile = await customers.update(profile.user_id, normalized);
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

  /**
   * Unmasked contact details for an identity-verified customer, read only by
   * Payment (service scope auth.customer-provider-profile.read) to open the
   * customer's provider account. Never exposed on a customer-facing route.
   */
  public providerProfile(
    tenantId: string,
    customerId: string,
  ): Promise<CustomerProviderProfile> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const row = await tx("customer_profiles as c")
        .join("users as u", "u.id", "c.user_id")
        .where({ "c.id": customerId })
        .whereNull("c.deleted_at")
        .whereExists(
          tx("kyc_profiles as k")
            .whereRaw("k.customer_id = c.id")
            .where({ "k.status": "VERIFIED" })
            .whereNull("k.deleted_at"),
        )
        .first<
          | {
              first_name: string | null;
              middle_name: string | null;
              last_name: string | null;
              email: string | null;
              phone: string | null;
            }
          | undefined
        >("c.first_name", "c.middle_name", "c.last_name", "u.email", "u.phone");
      if (!row)
        throw new ApiError(
          404,
          "VERIFIED_CUSTOMER_NOT_FOUND",
          "No identity-verified customer was found",
        );
      if (!row.first_name || !row.last_name || !row.email || !row.phone)
        throw new ApiError(
          409,
          "PROVIDER_PROFILE_INCOMPLETE",
          "The customer's name, email or phone is missing",
        );
      const stored = this.identityNumbers
        ? await tx("customer_identity_numbers")
            .where({ customer_id: customerId, identity_type: "BVN" })
            .first<
              | {
                  ciphertext: string;
                  iv: string;
                  auth_tag: string;
                  key_id: string;
                }
              | undefined
            >("ciphertext", "iv", "auth_tag", "key_id")
        : undefined;
      return {
        customer_id: customerId,
        first_name: row.first_name,
        middle_name: row.middle_name,
        last_name: row.last_name,
        email: row.email,
        phone_number: row.phone,
        bvn:
          stored && this.identityNumbers
            ? this.identityNumbers.decrypt(
                {
                  ciphertext: stored.ciphertext,
                  iv: stored.iv,
                  authTag: stored.auth_tag,
                  keyId: stored.key_id,
                },
                { tenantId, customerId, identityType: "BVN" },
              )
            : null,
      };
    });
  }
}
