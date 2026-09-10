import {
  createHmac,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import { AuthenticationRepository } from "../repositories/authentication-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import { UserRepository } from "../repositories/user-repository.js";
import type { OtpSecretStore } from "../security/otp-secret-store.js";
import type { RateLimiter } from "../security/rate-limiter.js";
import type { AuthResultIssuer } from "./authentication-service.js";
import type { AdministratorTenantAdminClient } from "./tenant-admin-client.js";

export interface CustomerMfaGate {
  challenge(input: {
    tenantId: string;
    userId: string;
    deviceId: string;
  }): Promise<{ mfa_required: true; challenge: object } | undefined>;
}

export class CustomerMfaService implements CustomerMfaGate {
  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: AdministratorTenantAdminClient,
    private readonly secrets: OtpSecretStore,
    private readonly limiter: RateLimiter,
    private readonly issuer: AuthResultIssuer,
    private readonly hashSecret: string,
  ) {}

  public async challenge(input: {
    tenantId: string;
    userId: string;
    deviceId: string;
  }): Promise<{ mfa_required: true; challenge: object } | undefined> {
    const policy = await this.tenantAdmin.getTenantAuthenticationPolicy(
      input.tenantId,
    );
    if (!policy.customer_mfa_required) return undefined;
    const method = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const user = await new UserRepository(transaction).findById(
          input.userId,
        );
        if (!user) return undefined;
        if (
          policy.allowed_customer_mfa_methods.includes("SMS_OTP") &&
          user.phone
        )
          return "SMS_OTP" as const;
        if (
          policy.allowed_customer_mfa_methods.includes("EMAIL_OTP") &&
          user.email
        )
          return "EMAIL_OTP" as const;
        return undefined;
      },
    );
    if (!method)
      throw new ApiError(
        403,
        "MFA_ENROLLMENT_REQUIRED",
        "Customer MFA enrollment is required",
      );
    const challengeId = randomUUID();
    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    const challenge = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const created = await new AuthenticationRepository(
          transaction,
        ).createChallenge({
          id: challengeId,
          tenantId: input.tenantId,
          userId: input.userId,
          subjectId: input.userId,
          subjectType: "CUSTOMER",
          scopeType: "TENANT",
          hash: this.hash(`${challengeId}:${code}`),
          type: method,
          purpose: "CUSTOMER_LOGIN_MFA",
          expiresAt,
        });
        const eventId = randomUUID();
        const occurredAt = new Date().toISOString();
        await new EventRepository(transaction).publish({
          tenantId: input.tenantId,
          eventId,
          eventType: "notification.requested.v1",
          aggregateType: "notification",
          aggregateId: eventId,
          payload: {
            event_id: eventId,
            event_type: "notification.requested.v1",
            event_version: 1,
            occurred_at: occurredAt,
            producer: "parc-auth-customer",
            tenant_id: input.tenantId,
            aggregate_type: "notification",
            aggregate_id: eventId,
            aggregate_version: 1,
            correlation_id: randomUUID(),
            causation_id: null,
            idempotency_key: challengeId,
            data_classification: "RESTRICTED",
            payload: {
              notification_id: eventId,
              recipient_id: input.userId,
              channel: method === "SMS_OTP" ? "SMS" : "EMAIL",
              template_code: "OTP_CUSTOMER_LOGIN_MFA",
              classification: "SECURITY",
              template_data: { challenge_id: challengeId },
            },
          },
        });
        return created;
      },
    );
    await this.secrets.put(
      challenge.id,
      JSON.stringify({ code, deviceId: input.deviceId }),
      5 * 60,
    );
    return {
      mfa_required: true,
      challenge: {
        challenge_id: challenge.id,
        expires_at: challenge.expires_at.toISOString(),
      },
    };
  }

  public async verify(input: {
    tenantId: string;
    challengeId: string;
    response: string;
    idempotencyKey: string;
  }): Promise<object> {
    if (
      !(await this.limiter.consume(
        `auth:customer-mfa:${input.tenantId}:${input.challengeId}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    const stored = await this.secrets.take(input.challengeId);
    let state: { code: string; deviceId: string } | undefined;
    try {
      state = stored ? (JSON.parse(stored) as typeof state) : undefined;
    } catch {
      state = undefined;
    }
    const result = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const repository = new AuthenticationRepository(transaction);
        const challenge = await repository.findChallengeByIdForUpdate(
          input.challengeId,
          input.tenantId,
        );
        const expected = challenge
          ? this.hash(`${challenge.id}:${input.response}`)
          : this.hash(`missing:${input.response}`);
        const actual = challenge?.challenge_hash ?? this.hash("missing");
        const valid = Boolean(
          challenge?.subject_id &&
          challenge.subject_type === "CUSTOMER" &&
          challenge.purpose === "CUSTOMER_LOGIN_MFA" &&
          !challenge.consumed_at &&
          challenge.expires_at.getTime() > Date.now() &&
          challenge.attempts < challenge.max_attempts &&
          state?.code === input.response &&
          timingSafeEqual(Buffer.from(expected), Buffer.from(actual)),
        );
        if (!valid || !challenge?.subject_id || !state) {
          if (challenge && !challenge.consumed_at)
            await repository.incrementChallengeFailure(
              challenge.id,
              input.tenantId,
            );
          return undefined;
        }
        await repository.consumeChallenge(challenge.id, input.tenantId);
        return {
          userId: challenge.subject_id,
          deviceId: state.deviceId,
          method: challenge.challenge_type,
        };
      },
    );
    if (!result)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    await this.secrets.delete(input.challengeId);
    return this.issuer.issue({
      tenantId: input.tenantId,
      userId: result.userId,
      deviceId: result.deviceId,
      authenticationMethods: ["PASSWORD", result.method, "MFA"],
      idempotencyKey: input.idempotencyKey,
    });
  }

  private hash(value: string): string {
    return createHmac("sha256", this.hashSecret).update(value).digest("hex");
  }
}
