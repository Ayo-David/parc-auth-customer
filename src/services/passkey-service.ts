import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import type { Knex } from "knex";
import { withAuthScopeTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import { AuthenticationRepository } from "../repositories/authentication-repository.js";
import {
  PasskeyRepository,
  type PasskeyRecord,
} from "../repositories/passkey-repository.js";
import { UserRepository } from "../repositories/user-repository.js";
import type { OtpSecretStore } from "../security/otp-secret-store.js";
import type { AuthResultIssuer } from "./authentication-service.js";
import type { SessionService } from "./session-service.js";
import type {
  AdministratorTenantAdminClient,
  TenantAuthenticationPolicy,
} from "./tenant-admin-client.js";

type Scope = "TENANT" | "PLATFORM";
type SubjectType = "CUSTOMER" | "ADMINISTRATOR";

export interface PasskeySubject {
  tenantId: string | null;
  subjectId: string;
  subjectType: SubjectType;
  scope: Scope;
  userName: string;
  displayName: string;
  authorizationVersion?: number;
}

interface CeremonyState {
  ceremony: "REGISTRATION" | "AUTHENTICATION";
  challenge: string;
  tenantId: string | null;
  subjectId: string | null;
  subjectType: SubjectType | null;
  scope: Scope;
  rpId: string;
  allowedOrigins: string[];
  friendlyName?: string;
  authorizationVersion?: number;
}

export interface WebAuthnAdapter {
  registrationOptions(
    input: Parameters<typeof generateRegistrationOptions>[0],
  ): Promise<PublicKeyCredentialCreationOptionsJSON>;
  authenticationOptions(
    input: Parameters<typeof generateAuthenticationOptions>[0],
  ): Promise<PublicKeyCredentialRequestOptionsJSON>;
  verifyRegistration(
    input: Parameters<typeof verifyRegistrationResponse>[0],
  ): Promise<VerifiedRegistrationResponse>;
  verifyAuthentication(
    input: Parameters<typeof verifyAuthenticationResponse>[0],
  ): Promise<VerifiedAuthenticationResponse>;
}

export const simpleWebAuthnAdapter: WebAuthnAdapter = {
  registrationOptions: generateRegistrationOptions,
  authenticationOptions: generateAuthenticationOptions,
  verifyRegistration: verifyRegistrationResponse,
  verifyAuthentication: verifyAuthenticationResponse,
};

export class PasskeyService {
  private readonly ttlSeconds = 5 * 60;

  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: AdministratorTenantAdminClient,
    private readonly secrets: OtpSecretStore,
    private readonly customerIssuer: AuthResultIssuer,
    private readonly sessions: SessionService,
    private readonly hashSecret: string,
    private readonly webAuthn: WebAuthnAdapter = simpleWebAuthnAdapter,
  ) {}

  public async createCustomerRegistrationOptions(
    tenantId: string,
    userId: string,
    friendlyName?: string,
  ): Promise<{ challenge_id: string; public_key_options: object }> {
    const user = await withAuthScopeTransaction(
      this.database,
      tenantId,
      "TENANT",
      (transaction) => new UserRepository(transaction).findById(userId),
    );
    if (user?.tenant_id !== tenantId)
      throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
    const userName = user.email ?? user.phone ?? user.id;
    return this.createRegistrationOptions(
      {
        tenantId,
        subjectId: user.id,
        subjectType: "CUSTOMER",
        scope: "TENANT",
        userName,
        displayName: userName,
      },
      friendlyName,
    );
  }

  public async createRegistrationOptions(
    subject: PasskeySubject,
    friendlyName?: string,
  ): Promise<{ challenge_id: string; public_key_options: object }> {
    this.validateSubject(subject);
    const policy = await this.passkeyPolicy(subject.tenantId);
    const existing = await withAuthScopeTransaction(
      this.database,
      subject.tenantId,
      subject.scope,
      (transaction) =>
        new PasskeyRepository(transaction).listForSubject(subject),
    );
    const options = await this.webAuthn.registrationOptions({
      rpName: policy.relying_party_name,
      rpID: policy.relying_party_id,
      userID: Buffer.from(subject.subjectId, "utf8"),
      userName: subject.userName,
      userDisplayName: subject.displayName,
      attestationType: "none",
      timeout: this.ttlSeconds * 1000,
      excludeCredentials: existing.map((credential) => ({
        id: credential.credential_id,
        transports: credential.transports,
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "required",
      },
    });
    return this.persistChallenge(
      {
        ceremony: "REGISTRATION",
        challenge: options.challenge,
        tenantId: subject.tenantId,
        subjectId: subject.subjectId,
        subjectType: subject.subjectType,
        scope: subject.scope,
        rpId: policy.relying_party_id,
        allowedOrigins: policy.allowed_origins,
        ...(friendlyName ? { friendlyName } : {}),
        ...(subject.authorizationVersion
          ? { authorizationVersion: subject.authorizationVersion }
          : {}),
      },
      options,
    );
  }

  public async verifyRegistration(input: {
    tenantId: string | null;
    scope: Scope;
    challengeId: string;
    credential: RegistrationResponseJSON;
  }): Promise<object> {
    const state = await this.challengeState(input.challengeId);
    this.requireState(state, input, "REGISTRATION");
    let verification: VerifiedRegistrationResponse;
    try {
      verification = await this.webAuthn.verifyRegistration({
        response: input.credential,
        expectedChallenge: state.challenge,
        expectedOrigin: state.allowedOrigins,
        expectedRPID: state.rpId,
        requireUserVerification: true,
      });
    } catch {
      throw new ApiError(
        401,
        "PASSKEY_VERIFICATION_FAILED",
        "Passkey verification failed",
      );
    }
    if (!verification.verified || !state.subjectId || !state.subjectType)
      throw new ApiError(
        401,
        "PASSKEY_VERIFICATION_FAILED",
        "Passkey verification failed",
      );
    const info = verification.registrationInfo;
    const subjectId = state.subjectId;
    const subjectType = state.subjectType;
    const record = await withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        const challenges = new AuthenticationRepository(transaction);
        await this.lockValidChallenge(challenges, state, input.challengeId);
        let created: PasskeyRecord;
        try {
          created = await new PasskeyRepository(transaction).create({
            tenantId: input.tenantId,
            userId: subjectType === "CUSTOMER" ? subjectId : null,
            subjectId,
            subjectType,
            scope: input.scope,
            credentialId: info.credential.id,
            publicKey: Buffer.from(info.credential.publicKey).toString(
              "base64url",
            ),
            relyingPartyId: info.rpID ?? state.rpId,
            aaguid: info.aaguid,
            signCount: BigInt(info.credential.counter),
            transports: info.credential.transports ?? [],
            backupEligible: info.credentialDeviceType === "multiDevice",
            backupState: info.credentialBackedUp,
            deviceType: info.credentialDeviceType,
            ...(state.friendlyName ? { friendlyName: state.friendlyName } : {}),
          });
        } catch (error) {
          if ((error as { code?: string }).code === "23505")
            throw new ApiError(
              409,
              "PASSKEY_ALREADY_REGISTERED",
              "Passkey is already registered",
            );
          throw error;
        }
        await challenges.consumeChallenge(input.challengeId, input.tenantId);
        return created;
      },
    );
    await this.secrets.delete(input.challengeId);
    return {
      id: record.id,
      credential_id: record.credential_id,
      friendly_name: record.friendly_name,
      created_at: record.created_at.toISOString(),
    };
  }

  public async createAuthenticationOptions(input: {
    tenantId: string | null;
    scope: Scope;
    identifier?: string;
    administrator?: Omit<PasskeySubject, "userName" | "displayName">;
  }): Promise<{ challenge_id: string; public_key_options: object }> {
    const policy = await this.passkeyPolicy(input.tenantId);
    const subject =
      input.administrator ??
      (await this.customerSubject(input.tenantId, input.identifier));
    const credentials =
      input.administrator && subject
        ? await withAuthScopeTransaction(
            this.database,
            input.tenantId,
            input.scope,
            (transaction) =>
              new PasskeyRepository(transaction).listForSubject(subject),
          )
        : [];
    const options = await this.webAuthn.authenticationOptions({
      rpID: policy.relying_party_id,
      timeout: this.ttlSeconds * 1000,
      userVerification: "required",
      ...(credentials.length
        ? {
            allowCredentials: credentials.map((credential) => ({
              id: credential.credential_id,
              transports: credential.transports,
            })),
          }
        : {}),
    });
    return this.persistChallenge(
      {
        ceremony: "AUTHENTICATION",
        challenge: options.challenge,
        tenantId: input.tenantId,
        subjectId: subject?.subjectId ?? null,
        subjectType: subject?.subjectType ?? null,
        scope: input.scope,
        rpId: policy.relying_party_id,
        allowedOrigins: policy.allowed_origins,
        ...(subject?.authorizationVersion
          ? { authorizationVersion: subject.authorizationVersion }
          : {}),
      },
      options,
    );
  }

  public async verifyAuthentication(input: {
    tenantId: string | null;
    scope: Scope;
    challengeId: string;
    credential: AuthenticationResponseJSON;
    deviceId?: string;
    idempotencyKey: string;
  }): Promise<object> {
    const state = await this.challengeState(input.challengeId);
    this.requireState(state, input, "AUTHENTICATION");
    const result = await withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        const challenges = new AuthenticationRepository(transaction);
        await this.lockValidChallenge(challenges, state, input.challengeId);
        const passkeys = new PasskeyRepository(transaction);
        const passkey = await passkeys.findByCredentialForUpdate(
          input.credential.id,
          input.tenantId,
          input.scope,
        );
        if (
          passkey?.relying_party_id !== state.rpId ||
          (state.subjectId && passkey.subject_id !== state.subjectId)
        )
          throw new ApiError(
            401,
            "PASSKEY_VERIFICATION_FAILED",
            "Passkey verification failed",
          );
        let verification: VerifiedAuthenticationResponse;
        try {
          verification = await this.webAuthn.verifyAuthentication({
            response: input.credential,
            expectedChallenge: state.challenge,
            expectedOrigin: state.allowedOrigins,
            expectedRPID: state.rpId,
            requireUserVerification: true,
            credential: {
              id: passkey.credential_id,
              publicKey: new Uint8Array(
                Buffer.from(passkey.public_key, "base64url"),
              ),
              counter: this.safeCounter(passkey.sign_count),
              transports: passkey.transports,
            },
          });
        } catch {
          throw new ApiError(
            401,
            "PASSKEY_VERIFICATION_FAILED",
            "Passkey verification failed",
          );
        }
        if (!verification.verified)
          throw new ApiError(
            401,
            "PASSKEY_VERIFICATION_FAILED",
            "Passkey verification failed",
          );
        const nextCounter = BigInt(verification.authenticationInfo.newCounter);
        const previousCounter = BigInt(passkey.sign_count);
        if (nextCounter !== 0n && nextCounter <= previousCounter)
          throw new ApiError(
            409,
            "PASSKEY_COUNTER_REPLAY",
            "Passkey counter replay detected",
          );
        if (
          !(await passkeys.updateCounter(
            passkey.id,
            previousCounter,
            nextCounter,
            verification.authenticationInfo.credentialBackedUp,
          ))
        )
          throw new ApiError(
            409,
            "PASSKEY_COUNTER_CONFLICT",
            "Passkey was used concurrently",
          );
        await challenges.consumeChallenge(input.challengeId, input.tenantId);
        return passkey;
      },
    );
    await this.secrets.delete(input.challengeId);
    if (result.subject_type === "CUSTOMER") {
      if (!result.tenant_id)
        throw new ApiError(
          401,
          "PASSKEY_SCOPE_INVALID",
          "Passkey scope is invalid",
        );
      return this.customerIssuer.issue({
        tenantId: result.tenant_id,
        userId: result.subject_id,
        ...(input.deviceId ? { deviceId: input.deviceId } : {}),
        authenticationMethods: ["PASSKEY"],
        idempotencyKey: input.idempotencyKey,
      });
    }
    const authorization = await this.tenantAdmin.getAdministratorAuthorization(
      result.subject_id,
    );
    if (
      state.authorizationVersion &&
      authorization.authorization_version !== state.authorizationVersion
    )
      throw new ApiError(401, "AUTHORIZATION_STALE", "Authorization changed");
    return this.sessions.issueAdministrator({
      tenantId: result.tenant_id,
      administratorId: result.subject_id,
      scope: result.scope_type,
      authorizationVersion: authorization.authorization_version,
      authenticationMethods: ["PASSKEY", "MFA"],
    });
  }

  private async persistChallenge(
    state: CeremonyState,
    options: object,
  ): Promise<{ challenge_id: string; public_key_options: object }> {
    const id = randomUUID();
    await withAuthScopeTransaction(
      this.database,
      state.tenantId,
      state.scope,
      (transaction) =>
        new AuthenticationRepository(transaction).createChallenge({
          id,
          tenantId: state.tenantId,
          ...(state.subjectId ? { subjectId: state.subjectId } : {}),
          ...(state.subjectType ? { subjectType: state.subjectType } : {}),
          ...(state.subjectType === "CUSTOMER" && state.subjectId
            ? { userId: state.subjectId }
            : {}),
          ...(state.subjectId ? { scopeType: state.scope } : {}),
          ...(state.authorizationVersion
            ? { authorizationVersion: state.authorizationVersion }
            : {}),
          hash: this.hash(state.challenge),
          type: "PASSKEY",
          purpose: `PASSKEY_${state.ceremony}`,
          expiresAt: new Date(Date.now() + this.ttlSeconds * 1000),
        }),
    );
    await this.secrets.put(id, JSON.stringify(state), this.ttlSeconds);
    return { challenge_id: id, public_key_options: options };
  }

  private async challengeState(id: string): Promise<CeremonyState> {
    const value = await this.secrets.take(id);
    if (!value)
      throw new ApiError(
        401,
        "PASSKEY_CHALLENGE_INVALID",
        "Passkey challenge is invalid or expired",
      );
    try {
      return JSON.parse(value) as CeremonyState;
    } catch {
      throw new ApiError(
        401,
        "PASSKEY_CHALLENGE_INVALID",
        "Passkey challenge is invalid or expired",
      );
    }
  }

  private requireState(
    state: CeremonyState,
    input: { tenantId: string | null; scope: Scope },
    ceremony: CeremonyState["ceremony"],
  ): void {
    if (
      state.ceremony !== ceremony ||
      state.scope !== input.scope ||
      state.tenantId !== input.tenantId
    )
      throw new ApiError(
        401,
        "PASSKEY_CHALLENGE_INVALID",
        "Passkey challenge is invalid or expired",
      );
  }

  private async lockValidChallenge(
    repository: AuthenticationRepository,
    state: CeremonyState,
    id: string,
  ): Promise<void> {
    const challenge = await repository.findChallengeByIdForUpdate(
      id,
      state.tenantId,
    );
    const expected = this.hash(state.challenge);
    const actual = challenge?.challenge_hash ?? this.hash("missing");
    if (
      !challenge ||
      challenge.consumed_at ||
      challenge.expires_at.getTime() <= Date.now() ||
      challenge.purpose !== `PASSKEY_${state.ceremony}` ||
      !timingSafeEqual(Buffer.from(expected), Buffer.from(actual))
    )
      throw new ApiError(
        401,
        "PASSKEY_CHALLENGE_INVALID",
        "Passkey challenge is invalid or expired",
      );
  }

  private async passkeyPolicy(
    tenantId: string | null,
  ): Promise<NonNullable<TenantAuthenticationPolicy["passkey"]>> {
    const policy = tenantId
      ? await this.tenantAdmin.getTenantAuthenticationPolicy(tenantId)
      : await this.tenantAdmin.getPlatformAuthenticationPolicy();
    if (!policy.passkey)
      throw new ApiError(
        422,
        "PASSKEY_NOT_AVAILABLE",
        "Passkeys are not enabled for this scope",
      );
    return policy.passkey;
  }

  private async customerSubject(
    tenantId: string | null,
    identifier?: string,
  ): Promise<Omit<PasskeySubject, "userName" | "displayName"> | undefined> {
    if (!tenantId || !identifier) return undefined;
    return withAuthScopeTransaction(
      this.database,
      tenantId,
      "TENANT",
      async (transaction) => {
        const user = await new UserRepository(
          transaction,
        ).findByCanonicalIdentifier(tenantId, identifier.trim().toLowerCase());
        return user
          ? {
              tenantId,
              subjectId: user.id,
              subjectType: "CUSTOMER",
              scope: "TENANT",
            }
          : undefined;
      },
    );
  }

  private validateSubject(subject: PasskeySubject): void {
    if (
      (subject.scope === "TENANT" && !subject.tenantId) ||
      (subject.scope === "PLATFORM" && subject.tenantId !== null) ||
      (subject.subjectType === "CUSTOMER" && subject.scope !== "TENANT")
    )
      throw new ApiError(
        400,
        "INVALID_SCOPE",
        "Passkey subject scope is invalid",
      );
  }

  private safeCounter(value: string): number {
    const counter = BigInt(value);
    if (counter > BigInt(Number.MAX_SAFE_INTEGER))
      throw new ApiError(
        409,
        "PASSKEY_COUNTER_UNSUPPORTED",
        "Passkey counter is too large",
      );
    return Number(counter);
  }

  private hash(value: string): string {
    return createHmac("sha256", this.hashSecret).update(value).digest("hex");
  }
}
