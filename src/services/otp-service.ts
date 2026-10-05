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
import { IdempotencyRepository } from "../repositories/idempotency-repository.js";
import { UserRepository } from "../repositories/user-repository.js";
import { CredentialRepository } from "../repositories/credential-repository.js";
import argon2 from "argon2";
import type { OtpSecretStore } from "../security/otp-secret-store.js";
import type { RateLimiter } from "../security/rate-limiter.js";
import type { AuthResultIssuer } from "./authentication-service.js";

export type OtpPurpose =
  | "LOGIN"
  | "PHONE_VERIFICATION"
  | "EMAIL_VERIFICATION"
  | "PASSWORD_RESET"
  | "STEP_UP";
export type OtpChannel = "SMS" | "EMAIL";

export class OtpService {
  public constructor(
    private readonly database: Knex,
    private readonly rateLimiter: RateLimiter,
    private readonly secrets: OtpSecretStore,
    private readonly issuer: AuthResultIssuer,
    private readonly hashSecret: string,
  ) {}

  public async request(input: {
    tenantId: string;
    idempotencyKey: string;
    purpose: OtpPurpose;
    channel: OtpChannel;
    destination: string;
  }): Promise<{ challenge_id: string; expires_at: string }> {
    const destination = input.destination.trim().toLowerCase();
    if (
      !(await this.rateLimiter.consume(
        `auth:otp:request:${input.tenantId}:${destination}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    let storedChallengeId: string | undefined;
    try {
      return await withTenantTransaction(
        this.database,
        input.tenantId,
        async (transaction) => {
          const idempotency = new IdempotencyRepository(transaction);
          const requestHash = this.hash(
            JSON.stringify({
              purpose: input.purpose,
              channel: input.channel,
              destination,
            }),
          );
          const claim = await idempotency.claim({
            tenantId: input.tenantId,
            key: input.idempotencyKey,
            operation: "otp.request",
            requestHash,
            expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
          });
          if (!claim.created) {
            if (claim.record.status === "COMPLETED")
              return claim.record.response_body as {
                challenge_id: string;
                expires_at: string;
              };
            throw new ApiError(
              409,
              "REQUEST_IN_PROGRESS",
              "An equivalent request is in progress",
            );
          }
          const matchedUser = await new UserRepository(
            transaction,
          ).findByCanonicalIdentifier(input.tenantId, destination);
          const user =
            matchedUser &&
            ((input.channel === "EMAIL" &&
              matchedUser.email_normalized === destination) ||
              (input.channel === "SMS" &&
                matchedUser.phone_normalized === destination))
              ? matchedUser
              : undefined;
          const challengeId = randomUUID();
          const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
          const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
          const challenge = await new AuthenticationRepository(
            transaction,
          ).createChallenge({
            id: challengeId,
            tenantId: input.tenantId,
            ...(user ? { userId: user.id } : {}),
            hash: this.hash(`${challengeId}:${code}`),
            type: "OTP",
            purpose: input.purpose,
            expiresAt,
          });
          storedChallengeId = challenge.id;
          await this.secrets.put(challenge.id, code, 5 * 60);
          if (user)
            await this.publishNotification(transaction, {
              tenantId: input.tenantId,
              userId: user.id,
              challengeId: challenge.id,
              channel: input.channel,
              purpose: input.purpose,
              idempotencyKey: input.idempotencyKey,
            });
          const response = {
            challenge_id: challenge.id,
            expires_at: challenge.expires_at.toISOString(),
          };
          await idempotency.complete({
            tenantId: input.tenantId,
            key: input.idempotencyKey,
            operation: "otp.request",
            responseCode: 202,
            responseBody: response,
          });
          return response;
        },
      );
    } catch (error) {
      if (storedChallengeId) await this.secrets.delete(storedChallengeId);
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

  public async verify(input: {
    tenantId: string;
    idempotencyKey: string;
    challengeId: string;
    code: string;
  }): Promise<object> {
    if (
      !(await this.rateLimiter.consume(
        `auth:otp:verify:${input.tenantId}:${input.challengeId}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    const code = await this.secrets.take(input.challengeId);
    const result = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const challenges = new AuthenticationRepository(transaction);
        const challenge = await challenges.findChallengeByIdForUpdate(
          input.challengeId,
          input.tenantId,
        );
        const validState =
          challenge?.challenge_type === "OTP" &&
          !challenge.consumed_at &&
          challenge.expires_at.getTime() > Date.now() &&
          challenge.attempts < challenge.max_attempts &&
          Boolean(challenge.user_id) &&
          Boolean(code);
        const expected = challenge
          ? this.hash(`${challenge.id}:${input.code}`)
          : this.hash(`missing:${input.code}`);
        const actual = challenge?.challenge_hash ?? this.hash("missing");
        const matches = timingSafeEqual(
          Buffer.from(expected),
          Buffer.from(actual),
        );
        if (!validState || !matches || !challenge.user_id) {
          if (challenge && !challenge.consumed_at)
            await challenges.incrementChallengeFailure(
              challenge.id,
              input.tenantId,
            );
          return undefined;
        }
        await challenges.consumeChallenge(challenge.id, input.tenantId);
        if (challenge.purpose === "PHONE_VERIFICATION")
          await transaction("users").where({ id: challenge.user_id }).update({
            phone_verified: true,
            phone_verified_at: transaction.fn.now(),
          });
        if (challenge.purpose === "EMAIL_VERIFICATION")
          await transaction("users").where({ id: challenge.user_id }).update({
            email_verified: true,
            email_verified_at: transaction.fn.now(),
          });
        return { userId: challenge.user_id };
      },
    );
    if (!result)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    await this.secrets.delete(input.challengeId);
    return this.issuer.issue({
      tenantId: input.tenantId,
      userId: result.userId,
      authenticationMethods: ["OTP"],
      idempotencyKey: input.idempotencyKey,
    });
  }

  public async resetLoginPasscode(input: {
    tenantId: string;
    idempotencyKey: string;
    challengeId: string;
    code: string;
    newPasscode: string;
  }): Promise<void> {
    if (
      !(await this.rateLimiter.consume(
        `auth:passcode-reset:${input.tenantId}:${input.challengeId}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    const code = await this.secrets.take(input.challengeId);
    let challengeExpiresAt: Date | undefined;
    const changed = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const idempotency = new IdempotencyRepository(transaction);
        const requestHash = this.hash(
          JSON.stringify({
            challengeId: input.challengeId,
            code: input.code,
            newPasscode: input.newPasscode,
          }),
        );
        const claim = await idempotency.claim({
          tenantId: input.tenantId,
          key: input.idempotencyKey,
          operation: "passcode.reset",
          requestHash,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        if (!claim.created && claim.record.status === "COMPLETED") return true;
        const challenges = new AuthenticationRepository(transaction);
        const challenge = await challenges.findChallengeByIdForUpdate(
          input.challengeId,
          input.tenantId,
        );
        const expected = challenge
          ? this.hash(`${challenge.id}:${input.code}`)
          : this.hash(`missing:${input.code}`);
        const actual = challenge?.challenge_hash ?? this.hash("missing");
        const valid =
          challenge?.challenge_type === "OTP" &&
          challenge.purpose === "PASSWORD_RESET" &&
          !challenge.consumed_at &&
          challenge.expires_at.getTime() > Date.now() &&
          challenge.attempts < challenge.max_attempts &&
          Boolean(challenge.user_id) &&
          Boolean(code) &&
          timingSafeEqual(Buffer.from(expected), Buffer.from(actual));
        if (!valid || !challenge.user_id) {
          if (challenge && !challenge.consumed_at)
            await challenges.incrementChallengeFailure(
              challenge.id,
              input.tenantId,
            );
          return false;
        }
        challengeExpiresAt = challenge.expires_at;
        const credentials = new CredentialRepository(transaction);
        const recent = await credentials.recentHashes(
          challenge.user_id,
          "LOGIN_PASSCODE",
          5,
        );
        for (const hash of recent)
          if (await argon2.verify(hash, input.newPasscode))
            throw new ApiError(
              422,
              "PASSCODE_REUSE",
              "A recent login passcode cannot be reused",
            );
        await credentials.replace({
          tenantId: input.tenantId,
          userId: challenge.user_id,
          type: "LOGIN_PASSCODE",
          hash: await argon2.hash(input.newPasscode, { type: argon2.argon2id }),
          reason: "CUSTOMER_RECOVERY",
        });
        await challenges.consumeChallenge(challenge.id, input.tenantId);
        await transaction("user_sessions")
          .where({ tenant_id: input.tenantId, subject_id: challenge.user_id })
          .whereNull("revoked_at")
          .update({
            revoked_at: transaction.fn.now(),
            refresh_token_hash: null,
          });
        await idempotency.complete({
          tenantId: input.tenantId,
          key: input.idempotencyKey,
          operation: "passcode.reset",
          responseCode: 204,
          responseBody: {},
        });
        return true;
      },
    ).catch(async (error: unknown) => {
      // A rejected passcode choice must not burn the still-valid OTP.
      const ttl = challengeExpiresAt
        ? Math.floor((challengeExpiresAt.getTime() - Date.now()) / 1000)
        : 0;
      if (
        error instanceof ApiError &&
        error.code === "PASSCODE_REUSE" &&
        code &&
        ttl > 0
      )
        await this.secrets.put(input.challengeId, code, ttl);
      throw error;
    });
    if (!changed)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    await this.secrets.delete(input.challengeId);
  }

  private hash(value: string): string {
    return createHmac("sha256", this.hashSecret).update(value).digest("hex");
  }

  private async publishNotification(
    transaction: Knex.Transaction,
    input: {
      tenantId: string;
      userId: string;
      challengeId: string;
      channel: OtpChannel;
      purpose: OtpPurpose;
      idempotencyKey: string;
    },
  ): Promise<void> {
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
        idempotency_key: input.idempotencyKey,
        data_classification: "RESTRICTED",
        payload: {
          notification_id: eventId,
          recipient_id: input.userId,
          channel: input.channel,
          template_code: `OTP_${input.purpose}`,
          classification: "SECURITY",
          template_data: { challenge_id: input.challengeId },
        },
      },
    });
  }
}
