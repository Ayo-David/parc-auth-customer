import {
  createHmac,
  randomInt,
  randomUUID,
  timingSafeEqual,
} from "node:crypto";
import type { Knex } from "knex";
import { withAuthScopeTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import {
  AuthenticationRepository,
  type ChallengeRecord,
} from "../repositories/authentication-repository.js";
import type { OtpSecretStore } from "../security/otp-secret-store.js";
import type { RateLimiter } from "../security/rate-limiter.js";
import type { SessionService, TokenPair } from "./session-service.js";
import type {
  AdministratorVerification,
  AdministratorTenantAdminClient,
} from "./tenant-admin-client.js";
import type { PasskeyService } from "./passkey-service.js";

type Scope = "TENANT" | "PLATFORM";
type MfaMethod = "TOTP" | "SMS_OTP" | "EMAIL_OTP" | "PASSKEY";

export class AdministratorAuthenticationService {
  private readonly challengeTtlSeconds = 5 * 60;

  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: AdministratorTenantAdminClient,
    private readonly sessions: SessionService,
    private readonly secrets: OtpSecretStore,
    private readonly rateLimiter: RateLimiter,
    private readonly hashSecret: string,
    private readonly passkeys?: PasskeyService,
  ) {}

  public async authenticate(input: {
    identifier: string;
    password: string;
    tenantContext: string | null;
    idempotencyKey: string;
  }): Promise<{ mfa_required: true; challenge: object }> {
    const administrator = await this.tenantAdmin.verifyAdministrator(input);
    // Administrators can never be downgraded to password-only by tenant policy.
    if (!administrator.mfa_required)
      throw new ApiError(
        403,
        "MFA_POLICY_INVALID",
        "Administrator MFA is required",
      );
    const method = await this.findUsableMethod(administrator);
    if (!method)
      throw new ApiError(
        403,
        "MFA_ENROLLMENT_REQUIRED",
        "Administrator MFA enrollment is required",
      );
    if (method === "PASSKEY") {
      if (!this.passkeys)
        throw new ApiError(
          503,
          "PASSKEY_UNAVAILABLE",
          "Passkey authentication is unavailable",
        );
      return {
        mfa_required: true,
        challenge: await this.passkeys.createAuthenticationOptions({
          tenantId: administrator.tenant_id,
          scope: administrator.scope,
          administrator: {
            tenantId: administrator.tenant_id,
            subjectId: administrator.administrator_id,
            subjectType: "ADMINISTRATOR",
            scope: administrator.scope,
            authorizationVersion: administrator.authorization_version,
          },
        }),
      };
    }
    return {
      mfa_required: true,
      challenge: await this.createChallenge(
        administrator,
        method,
        "ADMIN_LOGIN",
      ),
    };
  }

  public async enroll(input: {
    administratorId: string;
    tenantId: string | null;
    scope: Scope;
    method: MfaMethod;
    identifier?: string;
  }): Promise<object> {
    if (input.method === "PASSKEY" || input.method === "TOTP")
      throw new ApiError(
        422,
        "MFA_METHOD_NOT_AVAILABLE",
        "This MFA method is handled by its dedicated enrollment flow",
      );
    const challengeId = randomUUID();
    await withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        await transaction("user_2fa_methods").insert({
          id: challengeId,
          tenant_id: input.tenantId,
          user_id: null,
          subject_id: input.administratorId,
          subject_type: "ADMINISTRATOR",
          scope_type: input.scope,
          method_type: this.databaseMethod(input.method),
          identifier: input.identifier ?? null,
          is_verified: false,
        });
      },
    );
    return this.createChallenge(
      {
        administrator_id: input.administratorId,
        tenant_id: input.tenantId,
        scope: input.scope,
        status: "ACTIVE",
        roles: [],
        authorization_version: 1,
        mfa_required: true,
        allowed_mfa_methods: [input.method],
      },
      input.method,
      "ADMIN_MFA_ENROLLMENT",
      challengeId,
    );
  }

  public async verify(input: {
    tenantId: string | null;
    scope: Scope;
    challengeId: string;
    response: string;
  }): Promise<TokenPair | { enrolled: true }> {
    if (
      !(await this.rateLimiter.consume(
        `auth:admin-mfa:${input.scope}:${input.tenantId ?? "platform"}:${input.challengeId}`,
        5,
        15 * 60,
      ))
    )
      throw new ApiError(
        429,
        "RATE_LIMITED",
        "Too many authentication attempts",
      );
    const storedCode = await this.secrets.take(input.challengeId);
    const result = await withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        const repository = new AuthenticationRepository(transaction);
        const challenge = await repository.findChallengeByIdForUpdate(
          input.challengeId,
          input.tenantId,
        );
        if (!this.validChallenge(challenge, input, storedCode)) {
          if (challenge && !challenge.consumed_at)
            await repository.incrementChallengeFailure(
              challenge.id,
              input.tenantId,
            );
          return undefined;
        }
        await repository.consumeChallenge(challenge.id, input.tenantId);
        if (challenge.purpose === "ADMIN_MFA_ENROLLMENT") {
          await transaction("user_2fa_methods")
            .where({ id: challenge.id, subject_id: challenge.subject_id })
            .update({
              is_verified: true,
              verified_at: transaction.fn.now(),
              enabled_at: transaction.fn.now(),
            });
          return { challenge, enrolled: true as const };
        }
        return { challenge, enrolled: false as const };
      },
    );
    if (!result)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    await this.secrets.delete(input.challengeId);
    if (result.enrolled) return { enrolled: true };
    const challenge = result.challenge;
    const authorization = await this.tenantAdmin.getAdministratorAuthorization(
      challenge.subject_id,
    );
    if (authorization.authorization_version !== challenge.authorization_version)
      throw new ApiError(401, "AUTHORIZATION_STALE", "Authorization changed");
    return this.sessions.issueAdministrator({
      tenantId: challenge.tenant_id,
      administratorId: challenge.subject_id,
      scope: challenge.scope_type,
      authorizationVersion: authorization.authorization_version,
      authenticationMethods: ["PASSWORD", challenge.challenge_type, "MFA"],
    });
  }

  public async reset(input: {
    administratorId: string;
    tenantId: string | null;
    scope: Scope;
    method: MfaMethod;
    approvalId: string;
    reason: string;
    idempotencyKey: string;
  }): Promise<void> {
    if (!input.approvalId)
      throw new ApiError(
        403,
        "APPROVAL_REQUIRED",
        "Approved reset is required",
      );
    await this.tenantAdmin.consumeApproval({
      approvalId: input.approvalId,
      tenantId: input.tenantId,
      idempotencyKey: input.idempotencyKey,
      action: "ADMINISTRATOR_MFA_RESET",
      resourceId: input.administratorId,
      payloadHash: this.hash(
        JSON.stringify({
          administratorId: input.administratorId,
          scope: input.scope,
          method: input.method,
          reason: input.reason,
        }),
      ),
    });
    await withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        await transaction("user_2fa_methods")
          .where({
            subject_id: input.administratorId,
            subject_type: "ADMINISTRATOR",
            scope_type: input.scope,
            method_type: this.databaseMethod(input.method),
          })
          .whereNull("deleted_at")
          .update({ disabled_at: transaction.fn.now(), is_verified: false });
        await transaction("user_sessions")
          .where({
            subject_id: input.administratorId,
            subject_type: "ADMINISTRATOR",
          })
          .whereNull("revoked_at")
          .update({ revoked_at: transaction.fn.now() });
      },
    );
  }

  private async findUsableMethod(
    administrator: AdministratorVerification,
  ): Promise<MfaMethod | undefined> {
    return withAuthScopeTransaction(
      this.database,
      administrator.tenant_id,
      administrator.scope,
      async (transaction) => {
        const record = await transaction("user_2fa_methods")
          .where({
            subject_id: administrator.administrator_id,
            subject_type: "ADMINISTRATOR",
            scope_type: administrator.scope,
            is_verified: true,
          })
          .whereIn(
            "method_type",
            administrator.allowed_mfa_methods.map((method) =>
              this.databaseMethod(method),
            ),
          )
          .whereNull("disabled_at")
          .whereNull("deleted_at")
          .first();
        return record?.method_type
          ? this.contractMethod(record.method_type as string)
          : undefined;
      },
    );
  }

  private async createChallenge(
    administrator: AdministratorVerification,
    method: MfaMethod,
    purpose: "ADMIN_LOGIN" | "ADMIN_MFA_ENROLLMENT",
    fixedId?: string,
  ): Promise<{ challenge_id: string; expires_at: string }> {
    const challengeId = fixedId ?? randomUUID();
    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const expiresAt = new Date(Date.now() + this.challengeTtlSeconds * 1000);
    const challenge = await withAuthScopeTransaction(
      this.database,
      administrator.tenant_id,
      administrator.scope,
      (transaction) =>
        new AuthenticationRepository(transaction).createChallenge({
          id: challengeId,
          tenantId: administrator.tenant_id,
          subjectId: administrator.administrator_id,
          subjectType: "ADMINISTRATOR",
          scopeType: administrator.scope,
          authorizationVersion: administrator.authorization_version,
          hash: this.hash(`${challengeId}:${code}`),
          type: method,
          purpose,
          expiresAt,
        }),
    );
    await this.secrets.put(challenge.id, code, this.challengeTtlSeconds);
    return {
      challenge_id: challenge.id,
      expires_at: challenge.expires_at.toISOString(),
    };
  }

  private validChallenge(
    challenge: ChallengeRecord | undefined,
    input: { scope: Scope; response: string },
    storedCode: string | undefined,
  ): challenge is ChallengeRecord & {
    subject_id: string;
    subject_type: "ADMINISTRATOR";
    scope_type: Scope;
    authorization_version: number;
  } {
    const expected = challenge
      ? this.hash(`${challenge.id}:${input.response}`)
      : this.hash(`missing:${input.response}`);
    const actual = challenge?.challenge_hash ?? this.hash("missing");
    return Boolean(
      challenge?.subject_id &&
      challenge.subject_type === "ADMINISTRATOR" &&
      challenge.scope_type === input.scope &&
      challenge.authorization_version &&
      !challenge.consumed_at &&
      challenge.expires_at.getTime() > Date.now() &&
      challenge.attempts < challenge.max_attempts &&
      storedCode &&
      timingSafeEqual(Buffer.from(expected), Buffer.from(actual)),
    );
  }

  private hash(value: string): string {
    return createHmac("sha256", this.hashSecret).update(value).digest("hex");
  }

  private databaseMethod(method: MfaMethod): string {
    return {
      TOTP: "AUTHENTICATOR",
      SMS_OTP: "SMS",
      EMAIL_OTP: "EMAIL",
      PASSKEY: "PASSKEY",
    }[method];
  }

  private contractMethod(method: string): MfaMethod {
    const mapped = {
      AUTHENTICATOR: "TOTP",
      SMS: "SMS_OTP",
      EMAIL: "EMAIL_OTP",
      PASSKEY: "PASSKEY",
    }[method];
    if (!mapped) throw new Error("Unsupported MFA method in database");
    return mapped as MfaMethod;
  }
}
