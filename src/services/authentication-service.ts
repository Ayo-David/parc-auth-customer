import { createHmac, randomUUID } from "node:crypto";
import argon2 from "argon2";
import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import {
  AuthenticationRepository,
  isUserLocked,
} from "../repositories/authentication-repository.js";
import { CredentialRepository } from "../repositories/credential-repository.js";
import { UserRepository } from "../repositories/user-repository.js";
import { IdempotencyRepository } from "../repositories/idempotency-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import type { RateLimiter } from "../security/rate-limiter.js";
import type { CustomerMfaGate } from "./customer-mfa-service.js";

export interface AuthResultIssuer {
  issue(input: {
    tenantId: string;
    userId: string;
    deviceId?: string;
    authenticationMethods: readonly string[];
    idempotencyKey: string;
  }): Promise<object>;
}

export class PendingAuthResultIssuer implements AuthResultIssuer {
  public issue(): Promise<object> {
    return Promise.reject(
      new ApiError(
        503,
        "TOKEN_ISSUER_UNAVAILABLE",
        "Token issuance is not configured",
      ),
    );
  }
}

const dummyHash = argon2.hash("constant-time-placeholder-not-a-real-password", {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
});

export class AuthenticationService {
  public constructor(
    private readonly database: Knex,
    private readonly rateLimiter: RateLimiter,
    private readonly issuer: AuthResultIssuer,
    private readonly challengeSecret: string,
    private readonly customerMfa?: CustomerMfaGate,
  ) {}

  public async login(input: {
    tenantId: string;
    idempotencyKey: string;
    identifier: string;
    password: string;
    deviceId: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<object> {
    const identifier = input.identifier.trim().toLowerCase();
    const velocityKey = `auth:login:${input.tenantId}:${identifier}`;
    if (!(await this.rateLimiter.consume(velocityKey, 10, 15 * 60)))
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );

    const verified = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const user = await new UserRepository(
          transaction,
        ).findByCanonicalIdentifier(input.tenantId, identifier);
        const credentials = new CredentialRepository(transaction);
        const credential = user
          ? await credentials.findActive(user.id, "PASSWORD")
          : undefined;
        const valid = await argon2.verify(
          credential?.credential_hash ?? (await dummyHash),
          input.password,
        );
        const attempts = new AuthenticationRepository(transaction);
        if (
          !user ||
          !credential ||
          !valid ||
          !["ACTIVE", "PENDING"].includes(user.status) ||
          isUserLocked(user)
        ) {
          await attempts.recordAttempt({
            tenantId: input.tenantId,
            ...(user ? { userId: user.id } : {}),
            identifier,
            success: false,
            failureReason: "INVALID_CREDENTIALS",
            ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
            ...(input.userAgent ? { userAgent: input.userAgent } : {}),
          });
          if (user && !isUserLocked(user))
            await attempts.recordLoginFailure(user.id, 5, 15);
          const securityEventId = randomUUID();
          const occurredAt = new Date().toISOString();
          await new EventRepository(transaction).publish({
            tenantId: input.tenantId,
            eventId: securityEventId,
            eventType: "security.event-detected.v1",
            aggregateType: "security_event",
            aggregateId: securityEventId,
            payload: {
              event_id: securityEventId,
              event_type: "security.event-detected.v1",
              event_version: 1,
              occurred_at: occurredAt,
              producer: "parc-auth-customer",
              tenant_id: input.tenantId,
              aggregate_type: "security_event",
              aggregate_id: securityEventId,
              aggregate_version: 1,
              correlation_id: randomUUID(),
              causation_id: null,
              idempotency_key: input.idempotencyKey,
              data_classification: "CONFIDENTIAL",
              payload: {
                security_event_id: securityEventId,
                subject_id: user?.id ?? null,
                event_code: "PASSWORD_AUTHENTICATION_FAILED",
                severity: user && isUserLocked(user) ? "HIGH" : "MEDIUM",
                detected_at: occurredAt,
              },
            },
          });
          return { userId: undefined };
        }
        await attempts.recordLoginSuccess(user.id);
        await attempts.recordAttempt({
          tenantId: input.tenantId,
          userId: user.id,
          identifier,
          success: true,
          ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
          ...(input.userAgent ? { userAgent: input.userAgent } : {}),
        });
        await credentials.touchLastUsed(credential.id);
        return { userId: user.id };
      },
    );
    if (!verified.userId)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    const mfa = await this.customerMfa?.challenge({
      tenantId: input.tenantId,
      userId: verified.userId,
      deviceId: input.deviceId,
    });
    if (mfa) return mfa;
    return this.issuer.issue({
      tenantId: input.tenantId,
      userId: verified.userId,
      deviceId: input.deviceId,
      authenticationMethods: ["PASSWORD"],
      idempotencyKey: input.idempotencyKey,
    });
  }

  public async loginWithPasscode(input: {
    tenantId: string;
    idempotencyKey: string;
    identifier: string;
    passcode: string;
    deviceId: string;
  }): Promise<object> {
    const identifier = input.identifier.trim().toLowerCase();
    if (
      !(await this.rateLimiter.consume(
        `auth:passcode:${input.tenantId}:${identifier}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    const userId = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const user = await new UserRepository(
          transaction,
        ).findByCanonicalIdentifier(input.tenantId, identifier);
        const repository = new CredentialRepository(transaction);
        const credential = user
          ? await repository.findActive(user.id, "LOGIN_PASSCODE")
          : undefined;
        const valid = await argon2.verify(
          credential?.credential_hash ?? (await dummyHash),
          input.passcode,
        );
        if (
          !user ||
          !credential ||
          !valid ||
          !["ACTIVE", "PENDING"].includes(user.status) ||
          isUserLocked(user)
        ) {
          if (user && !isUserLocked(user))
            await new AuthenticationRepository(transaction).recordLoginFailure(
              user.id,
              5,
              15,
            );
          return undefined;
        }
        await new AuthenticationRepository(transaction).recordLoginSuccess(
          user.id,
        );
        await repository.touchLastUsed(credential.id);
        return user.id;
      },
    );
    if (!userId)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    const mfa = await this.customerMfa?.challenge({
      tenantId: input.tenantId,
      userId,
      deviceId: input.deviceId,
    });
    if (mfa) return mfa;
    return this.issuer.issue({
      tenantId: input.tenantId,
      userId,
      deviceId: input.deviceId,
      authenticationMethods: ["LOGIN_PASSCODE"],
      idempotencyKey: input.idempotencyKey,
    });
  }

  public startPinSetup(
    tenantId: string,
    userId: string,
    idempotencyKey: string,
  ): Promise<{ challenge_id: string; expires_at: string }> {
    return withTenantTransaction(this.database, tenantId, async (transaction) =>
      this.idempotent(
        transaction,
        tenantId,
        idempotencyKey,
        "transaction-pin.setup",
        this.fingerprint({ userId }),
        201,
        async () => {
          const id = randomUUID();
          const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
          const hash = createHmac("sha256", this.challengeSecret)
            .update(id)
            .digest("hex");
          const challenge = await new AuthenticationRepository(
            transaction,
          ).createChallenge({
            id,
            tenantId,
            userId,
            hash,
            purpose: "TRANSACTION_PIN_SETUP",
            expiresAt,
          });
          return {
            challenge_id: challenge.id,
            expires_at: challenge.expires_at.toISOString(),
          };
        },
      ),
    );
  }

  public confirmPin(
    tenantId: string,
    userId: string,
    idempotencyKey: string,
    challengeId: string,
    pin: string,
  ): Promise<void> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        await this.idempotent(
          transaction,
          tenantId,
          idempotencyKey,
          "transaction-pin.confirm",
          this.fingerprint({ userId, challengeId, pin }),
          204,
          async () => {
            const authentication = new AuthenticationRepository(transaction);
            const challenge = await authentication.findChallengeForUpdate(
              challengeId,
              userId,
              tenantId,
            );
            if (
              challenge?.purpose !== "TRANSACTION_PIN_SETUP" ||
              challenge.consumed_at !== null ||
              challenge.expires_at.getTime() <= Date.now() ||
              challenge.attempts >= challenge.max_attempts
            )
              throw new ApiError(
                409,
                "INVALID_CHALLENGE",
                "Challenge is invalid or expired",
              );
            const credentials = new CredentialRepository(transaction);
            if (await credentials.findActive(userId, "PIN"))
              throw new ApiError(
                409,
                "PIN_ALREADY_CONFIGURED",
                "Transaction PIN is already configured",
              );
            await credentials.create({
              tenantId,
              userId,
              type: "PIN",
              hash: await argon2.hash(pin, { type: argon2.argon2id }),
            });
            await authentication.consumeChallenge(challenge.id, tenantId);
            return {};
          },
        );
      },
    );
  }

  public rotatePin(
    tenantId: string,
    userId: string,
    idempotencyKey: string,
    currentPin: string,
    newPin: string,
  ): Promise<void> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        await this.idempotent(
          transaction,
          tenantId,
          idempotencyKey,
          "transaction-pin.rotate",
          this.fingerprint({ userId, currentPin, newPin }),
          204,
          async () => {
            const credentials = new CredentialRepository(transaction);
            const current = await credentials.findActive(userId, "PIN");
            if (
              !current ||
              !(await argon2.verify(current.credential_hash, currentPin))
            )
              throw new ApiError(
                401,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
              );
            const recent = await credentials.recentHashes(userId, "PIN", 5);
            for (const hash of recent)
              if (await argon2.verify(hash, newPin))
                throw new ApiError(
                  422,
                  "PIN_REUSE",
                  "A recent transaction PIN cannot be reused",
                );
            await credentials.replace({
              tenantId,
              userId,
              type: "PIN",
              hash: await argon2.hash(newPin, { type: argon2.argon2id }),
              reason: "CUSTOMER_ROTATION",
            });
            return {};
          },
        );
      },
    );
  }

  public async verifyPin(
    tenantId: string,
    userId: string,
    idempotencyKey: string,
    pin: string,
  ): Promise<void> {
    if (
      !(await this.rateLimiter.consume(
        `auth:pin:${tenantId}:${userId}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    await withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        await this.idempotent(
          transaction,
          tenantId,
          idempotencyKey,
          "transaction-pin.verify",
          this.fingerprint({ userId, pin }),
          204,
          async () => {
            const credential = await new CredentialRepository(
              transaction,
            ).findActive(userId, "PIN");
            if (
              !credential ||
              !(await argon2.verify(credential.credential_hash, pin))
            )
              throw new ApiError(
                401,
                "AUTHENTICATION_FAILED",
                "Authentication failed",
              );
            await new CredentialRepository(transaction).touchLastUsed(
              credential.id,
            );
            return {};
          },
        );
      },
    );
  }

  private fingerprint(value: object): string {
    return createHmac("sha256", this.challengeSecret)
      .update(JSON.stringify(value))
      .digest("hex");
  }

  private async idempotent<T extends object>(
    transaction: Knex.Transaction,
    tenantId: string,
    key: string,
    operation: string,
    requestHash: string,
    responseCode: number,
    action: () => Promise<T>,
  ): Promise<T> {
    const idempotency = new IdempotencyRepository(transaction);
    let claim;
    try {
      claim = await idempotency.claim({
        tenantId,
        key,
        operation,
        requestHash,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
    } catch (error) {
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
    if (!claim.created) {
      if (claim.record.status === "COMPLETED")
        return claim.record.response_body as T;
      throw new ApiError(
        409,
        "REQUEST_IN_PROGRESS",
        "An equivalent request is in progress",
      );
    }
    const response = await action();
    await idempotency.complete({
      tenantId,
      key,
      operation,
      responseCode,
      responseBody: response,
    });
    return response;
  }
}
