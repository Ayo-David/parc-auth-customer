import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type { Knex } from "knex";
import { jwtVerify, SignJWT } from "jose";
import {
  withAuthScopeTransaction,
  withTenantTransaction,
} from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import { SessionRepository } from "../repositories/session-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import type { SessionRecord } from "../repositories/types.js";
import type {
  AccessTokenVerifier,
  AuthenticatedCustomer,
} from "../security/access-token-verifier.js";
import type { JwtKeyRing } from "../security/jwt-key-ring.js";
import type { AuthResultIssuer } from "./authentication-service.js";
import type { AdministratorTenantAdminClient } from "./tenant-admin-client.js";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
}

interface AccessClaims {
  sub: string;
  tenant_id: string | null;
  session_id: string;
  jti: string;
  aud: string | string[];
  exp: number;
  subject_type: "CUSTOMER" | "ADMINISTRATOR";
  scope?: "TENANT" | "PLATFORM";
  authorization_version: number | null;
  authentication_methods: string[];
}

export class SessionService implements AuthResultIssuer, AccessTokenVerifier {
  private readonly accessTtlSeconds = 15 * 60;
  private readonly refreshTtlMs = 30 * 24 * 60 * 60 * 1000;
  private readonly idleTtlMs = 7 * 24 * 60 * 60 * 1000;
  private readonly administratorAccessTtlSeconds = 5 * 60;
  private readonly administratorRefreshTtlMs = 8 * 60 * 60 * 1000;
  private readonly administratorIdleTtlMs = 15 * 60 * 1000;

  public constructor(
    private readonly database: Knex,
    private readonly keys: JwtKeyRing,
    private readonly issuer: string,
    private readonly tokenHashSecret: string,
    private readonly tenantAdmin?: AdministratorTenantAdminClient,
  ) {}

  public issue(input: {
    tenantId: string;
    userId: string;
    deviceId?: string;
    authenticationMethods: readonly string[];
    idempotencyKey: string;
  }): Promise<TokenPair> {
    return withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        if (input.deviceId)
          await this.ensureDevice(
            transaction,
            input.tenantId,
            input.userId,
            input.deviceId,
          );
        const refreshToken = randomBytes(48).toString("base64url");
        const jti = randomUUID();
        const session = await new SessionRepository(transaction).create({
          tenantId: input.tenantId,
          userId: input.userId,
          subjectId: input.userId,
          sessionTokenHash: this.hash(jti),
          refreshTokenHash: this.hash(refreshToken),
          tokenFamilyId: randomUUID(),
          rotationSequence: 0,
          audience: "mobile-bff",
          subjectType: "CUSTOMER",
          scopeType: "TENANT",
          authenticationMethods: [...input.authenticationMethods],
          expiresAt: new Date(Date.now() + this.refreshTtlMs),
          idleExpiresAt: new Date(Date.now() + this.idleTtlMs),
          ...(input.deviceId ? { deviceId: input.deviceId } : {}),
        });
        return this.pair(session, jti, refreshToken);
      },
    );
  }

  public async refresh(
    tenantId: string | null,
    refreshToken: string,
    scope: "TENANT" | "PLATFORM" = "TENANT",
  ): Promise<TokenPair> {
    const result = await withAuthScopeTransaction(
      this.database,
      tenantId,
      scope,
      async (transaction) => {
        const sessions = new SessionRepository(transaction);
        const current = await sessions.findByRefreshTokenHashForUpdate(
          tenantId,
          this.hash(refreshToken),
        );
        if (!current) return { state: "INVALID" as const };
        const now = new Date();
        if (
          current.revoked_at ||
          current.expires_at <= now ||
          (current.idle_expires_at && current.idle_expires_at <= now)
        ) {
          await sessions.markFamilyCompromised(current.token_family_id, now);
          await this.publishRevocation(
            transaction,
            current,
            "REFRESH_TOKEN_REUSE",
            now,
          );
          return { state: "REUSED" as const };
        }
        const nextRefreshToken = randomBytes(48).toString("base64url");
        const jti = randomUUID();
        const successor = await sessions.create({
          tenantId,
          userId: current.user_id,
          subjectId: current.subject_id,
          sessionTokenHash: this.hash(jti),
          refreshTokenHash: this.hash(nextRefreshToken),
          tokenFamilyId: current.token_family_id,
          rotationSequence: current.rotation_sequence + 1,
          audience: current.audience,
          subjectType: current.subject_type,
          scopeType: current.scope_type,
          ...(current.authorization_version
            ? { authorizationVersion: current.authorization_version }
            : {}),
          authenticationMethods: current.authentication_methods,
          expiresAt: current.expires_at,
          idleExpiresAt: new Date(
            Date.now() +
              (current.subject_type === "ADMINISTRATOR"
                ? this.administratorIdleTtlMs
                : this.idleTtlMs),
          ),
          ...(current.device_id ? { deviceId: current.device_id } : {}),
        });
        await sessions.replace(current.id, successor.id);
        return {
          state: "ROTATED" as const,
          pair: await this.pair(successor, jti, nextRefreshToken),
        };
      },
    );
    if (result.state === "ROTATED") return result.pair;
    throw new ApiError(
      result.state === "REUSED" ? 409 : 401,
      result.state === "REUSED"
        ? "REFRESH_TOKEN_REUSED"
        : "AUTHENTICATION_FAILED",
      result.state === "REUSED"
        ? "Refresh token reuse detected"
        : "Authentication failed",
    );
  }

  public async verify(token: string): Promise<AuthenticatedCustomer> {
    const { payload } = await jwtVerify(
      token,
      (header) => {
        const key = header.kid
          ? this.keys.publicKeys.get(header.kid)
          : undefined;
        if (!key)
          throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
        return key;
      },
      { issuer: this.issuer, audience: "mobile-bff", algorithms: ["RS256"] },
    );
    const claims = payload as unknown as AccessClaims;
    if (
      !claims.sub ||
      !claims.tenant_id ||
      !claims.session_id ||
      !claims.jti ||
      claims.subject_type !== "CUSTOMER"
    )
      throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
    const active = await withTenantTransaction(
      this.database,
      claims.tenant_id,
      async (transaction) => {
        const session = await new SessionRepository(transaction).findById(
          claims.tenant_id,
          claims.session_id,
        );
        return Boolean(
          session &&
          !session.revoked_at &&
          session.expires_at.getTime() > Date.now() &&
          (!session.idle_expires_at ||
            session.idle_expires_at.getTime() > Date.now()) &&
          session.session_token_hash === this.hash(claims.jti),
        );
      },
    );
    if (!active)
      throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
    return {
      subject: claims.sub,
      tenantId: claims.tenant_id,
      audience: "mobile-bff",
      sessionId: claims.session_id,
    };
  }

  public issueAdministrator(input: {
    tenantId: string | null;
    administratorId: string;
    scope: "TENANT" | "PLATFORM";
    authorizationVersion: number;
    authenticationMethods: readonly string[];
  }): Promise<TokenPair> {
    if (!input.authenticationMethods.includes("MFA"))
      throw new ApiError(403, "MFA_REQUIRED", "Administrator MFA is required");
    return withAuthScopeTransaction(
      this.database,
      input.tenantId,
      input.scope,
      async (transaction) => {
        const refreshToken = randomBytes(48).toString("base64url");
        const jti = randomUUID();
        const session = await new SessionRepository(transaction).create({
          tenantId: input.tenantId,
          userId: null,
          subjectId: input.administratorId,
          sessionTokenHash: this.hash(jti),
          refreshTokenHash: this.hash(refreshToken),
          tokenFamilyId: randomUUID(),
          rotationSequence: 0,
          audience: "admin-bff",
          subjectType: "ADMINISTRATOR",
          scopeType: input.scope,
          authorizationVersion: input.authorizationVersion,
          authenticationMethods: [...input.authenticationMethods],
          expiresAt: new Date(Date.now() + this.administratorRefreshTtlMs),
          idleExpiresAt: new Date(Date.now() + this.administratorIdleTtlMs),
        });
        return this.pair(session, jti, refreshToken);
      },
    );
  }

  public logout(tenantId: string, sessionId: string): Promise<void> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        const sessions = new SessionRepository(transaction);
        const session = await sessions.findById(tenantId, sessionId);
        if (!session || session.revoked_at) return;
        const revokedAt = new Date();
        await sessions.revokeSession(tenantId, sessionId);
        await this.publishRevocation(
          transaction,
          session,
          "CUSTOMER_LOGOUT",
          revokedAt,
        );
      },
    );
  }

  public async introspect(token: string, audience?: string): Promise<object> {
    try {
      const { payload } = await jwtVerify(
        token,
        (header) => {
          const key = header.kid
            ? this.keys.publicKeys.get(header.kid)
            : undefined;
          if (!key) throw new Error("Unknown key");
          return key;
        },
        {
          issuer: this.issuer,
          audience: audience ?? "mobile-bff",
          algorithms: ["RS256"],
        },
      );
      const claims = payload as unknown as AccessClaims;
      if (
        !claims.sub ||
        !claims.session_id ||
        !claims.jti ||
        !claims.scope ||
        (claims.scope === "TENANT" && !claims.tenant_id) ||
        (claims.scope === "PLATFORM" && claims.tenant_id !== null)
      )
        return { active: false };
      const session = await withAuthScopeTransaction(
        this.database,
        claims.tenant_id,
        claims.scope,
        (transaction) =>
          new SessionRepository(transaction).findById(
            claims.tenant_id,
            claims.session_id,
          ),
      );
      if (
        !session ||
        session.revoked_at ||
        session.expires_at.getTime() <= Date.now() ||
        (session.idle_expires_at &&
          session.idle_expires_at.getTime() <= Date.now()) ||
        session.session_token_hash !== this.hash(claims.jti) ||
        session.subject_id !== claims.sub ||
        session.subject_type !== claims.subject_type
      )
        return { active: false };
      if (claims.subject_type === "ADMINISTRATOR") {
        if (!this.tenantAdmin || claims.authorization_version === null)
          return { active: false };
        const authorization =
          await this.tenantAdmin.getAdministratorAuthorization(claims.sub);
        if (
          authorization.authorization_version !== claims.authorization_version
        ) {
          await this.revokeWithoutEvent(
            claims.tenant_id,
            claims.scope,
            claims.session_id,
          );
          return { active: false };
        }
      }
      return {
        active: true,
        subject: claims.sub,
        tenant_id: claims.tenant_id,
        subject_type: claims.subject_type,
        scope: claims.scope,
        authorization_version: claims.authorization_version,
        session_id: claims.session_id,
        audience: Array.isArray(payload.aud) ? payload.aud : [payload.aud],
        expires_at: new Date((payload.exp ?? 0) * 1000).toISOString(),
      };
    } catch {
      return { active: false };
    }
  }

  private async pair(
    session: Awaited<ReturnType<SessionRepository["create"]>>,
    jti: string,
    refreshToken: string,
  ): Promise<TokenPair> {
    const accessToken = await new SignJWT({
      tenant_id: session.tenant_id,
      session_id: session.id,
      subject_type: session.subject_type,
      scope: session.scope_type,
      authorization_version: session.authorization_version,
      authentication_methods: session.authentication_methods,
    })
      .setProtectedHeader({
        alg: "RS256",
        kid: this.keys.activeKid,
        typ: "JWT",
      })
      .setIssuer(this.issuer)
      .setAudience(session.audience)
      .setSubject(session.subject_id)
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime(
        Math.floor(Date.now() / 1000) +
          (session.subject_type === "ADMINISTRATOR"
            ? this.administratorAccessTtlSeconds
            : this.accessTtlSeconds),
      )
      .sign(this.keys.privateKey);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: "Bearer",
      expires_in:
        session.subject_type === "ADMINISTRATOR"
          ? this.administratorAccessTtlSeconds
          : this.accessTtlSeconds,
    };
  }

  private hash(value: string): string {
    return createHmac("sha256", this.tokenHashSecret)
      .update(value)
      .digest("hex");
  }

  private async ensureDevice(
    transaction: Knex.Transaction,
    tenantId: string,
    userId: string,
    deviceId: string,
  ): Promise<void> {
    await transaction("user_devices")
      .insert({
        id: deviceId,
        tenant_id: tenantId,
        user_id: userId,
        device_identifier: deviceId,
      })
      .onConflict("id")
      .ignore();
    const device = await transaction("user_devices")
      .where({ id: deviceId, tenant_id: tenantId, user_id: userId })
      .whereNull("deleted_at")
      .first();
    if (!device)
      throw new ApiError(
        409,
        "DEVICE_CONFLICT",
        "Device is associated with another identity",
      );
  }

  private async publishRevocation(
    transaction: Knex.Transaction,
    session: SessionRecord,
    reason: string,
    revokedAt: Date,
  ): Promise<void> {
    if (session.tenant_id === null) return;
    const eventId = randomUUID();
    await new EventRepository(transaction).publish({
      tenantId: session.tenant_id,
      eventId,
      eventType: "session.revoked.v1",
      aggregateType: "session",
      aggregateId: session.id,
      payload: {
        event_id: eventId,
        event_type: "session.revoked.v1",
        event_version: 1,
        occurred_at: revokedAt.toISOString(),
        producer: "parc-auth-customer",
        tenant_id: session.tenant_id,
        aggregate_type: "session",
        aggregate_id: session.id,
        aggregate_version: session.rotation_sequence + 1,
        correlation_id: randomUUID(),
        causation_id: null,
        idempotency_key: eventId,
        data_classification: "CONFIDENTIAL",
        payload: {
          session_id: session.id,
          subject_id: session.subject_id,
          subject_type: session.subject_type,
          reason,
          revoked_at: revokedAt.toISOString(),
        },
      },
    });
  }

  private revokeWithoutEvent(
    tenantId: string | null,
    scope: "TENANT" | "PLATFORM",
    sessionId: string,
  ): Promise<void> {
    return withAuthScopeTransaction(
      this.database,
      tenantId,
      scope,
      async (transaction) => {
        await new SessionRepository(transaction).revokeSession(
          tenantId,
          sessionId,
        );
      },
    );
  }
}
