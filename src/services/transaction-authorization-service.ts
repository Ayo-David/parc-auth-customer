import { createHmac } from "node:crypto";
import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";

type Method = "transaction_pin" | "biometric";

interface AuthorizationRow {
  id: string;
  customer_id: string;
  command_type: string;
  resource_id: string;
  status: "ACTIVE" | "CONSUMED" | "REVOKED";
  expires_at: Date;
  consumed_by_service: string | null;
  consumption_idempotency_key: string | null;
  token_hash: string;
  request_hash: string;
}

export interface TransactionStepUpVerifier {
  verify(input: {
    tenantId: string;
    customerId: string;
    idempotencyKey: string;
    method: Method;
    pin?: string;
    biometricChallengeId?: string;
    biometricAssertion?: string;
  }): Promise<void>;
}

export class TransactionAuthorizationService {
  public constructor(
    private readonly database: Knex,
    private readonly verifier: TransactionStepUpVerifier,
    private readonly tokenHashSecret: string,
    private readonly ttlSeconds = 300,
  ) {}

  private hash(value: string): string {
    return createHmac("sha256", this.tokenHashSecret)
      .update(value)
      .digest("hex");
  }

  public async issue(input: {
    tenantId: string;
    customerId: string;
    idempotencyKey: string;
    commandType: string;
    resourceId: string;
    requestHash: string;
    method: Method;
    pin?: string;
    biometricChallengeId?: string;
    biometricAssertion?: string;
  }): Promise<{ authorization_token: string; expires_at: string }> {
    await this.verifier.verify(input);
    const token = createHmac("sha256", this.tokenHashSecret)
      .update(
        [input.tenantId, input.customerId, input.idempotencyKey].join(":"),
      )
      .digest("base64url");
    const expiresAt = new Date(Date.now() + this.ttlSeconds * 1_000);
    return withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const findExisting = () =>
          transaction<AuthorizationRow>("transaction_authorizations")
            .where("tenant_id", input.tenantId)
            .andWhere("issue_idempotency_key", input.idempotencyKey)
            .first();
        const replay = (existing: AuthorizationRow) => {
          if (
            existing.customer_id !== input.customerId ||
            existing.command_type !== input.commandType ||
            existing.resource_id !== input.resourceId ||
            existing.request_hash !== input.requestHash ||
            existing.token_hash !== this.hash(token)
          )
            throw new ApiError(
              409,
              "IDEMPOTENCY_CONFLICT",
              "Idempotency key was reused with a different request",
            );
          return {
            authorization_token: token,
            expires_at: existing.expires_at.toISOString(),
          };
        };
        const existing = await findExisting();
        if (existing) return replay(existing);
        try {
          // Savepoint, so a concurrent duplicate leaves the transaction usable.
          await transaction.transaction((savepoint) =>
            savepoint("transaction_authorizations").insert({
              tenant_id: input.tenantId,
              customer_id: input.customerId,
              command_type: input.commandType,
              resource_id: input.resourceId,
              request_hash: input.requestHash,
              authorization_method: input.method,
              token_hash: this.hash(token),
              issue_idempotency_key: input.idempotencyKey,
              expires_at: expiresAt,
            }),
          );
        } catch (error) {
          if ((error as { code?: unknown }).code !== "23505") throw error;
          const raced = await findExisting();
          if (!raced) throw error;
          return replay(raced);
        }
        return {
          authorization_token: token,
          expires_at: expiresAt.toISOString(),
        };
      },
    );
  }

  public async consume(input: {
    tenantId: string;
    customerId: string;
    commandType: string;
    resourceId: string;
    token: string;
    serviceName: string;
    idempotencyKey: string;
  }): Promise<{
    authorization_reference: string;
    customer_id: string;
    subject: string;
    replayed: boolean;
  }> {
    return withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const row = await transaction<AuthorizationRow>(
          "transaction_authorizations",
        )
          .where("tenant_id", input.tenantId)
          .andWhere("token_hash", this.hash(input.token))
          .forUpdate()
          .first();
        if (
          row?.customer_id !== input.customerId ||
          row.command_type !== input.commandType ||
          row.resource_id !== input.resourceId
        )
          throw new ApiError(
            401,
            "AUTHORIZATION_INVALID",
            "Transaction authorization is invalid",
          );
        if (row.status === "CONSUMED") {
          if (
            row.consumption_idempotency_key !== input.idempotencyKey ||
            row.consumed_by_service !== input.serviceName
          )
            throw new ApiError(
              409,
              "AUTHORIZATION_ALREADY_CONSUMED",
              "Transaction authorization was already consumed",
            );
          return {
            authorization_reference: row.id,
            customer_id: row.customer_id,
            subject: row.customer_id,
            replayed: true,
          };
        }
        if (row.status !== "ACTIVE" || row.expires_at.getTime() <= Date.now())
          throw new ApiError(
            401,
            "AUTHORIZATION_EXPIRED",
            "Transaction authorization is expired or revoked",
          );
        await transaction("transaction_authorizations")
          .where({ id: row.id, status: "ACTIVE" })
          .update({
            status: "CONSUMED",
            consumed_at: transaction.fn.now(),
            consumed_by_service: input.serviceName,
            consumption_idempotency_key: input.idempotencyKey,
          });
        return {
          authorization_reference: row.id,
          customer_id: row.customer_id,
          subject: row.customer_id,
          replayed: false,
        };
      },
    );
  }
}
