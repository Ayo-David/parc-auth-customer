import { randomUUID } from "node:crypto";
import { jwtVerify, SignJWT, type JWTPayload } from "jose";
import { z } from "zod";
import type { JwtKeyRing } from "../security/jwt-key-ring.js";
import type { ScopeCatalogue } from "../security/scope-catalogue.js";
import type {
  AdministratorTenantAdminClient,
  ServiceAuthorization,
  TenantStatusReader,
} from "./tenant-admin-client.js";

export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "invalid_scope"
  | "unsupported_grant_type";

export class OAuthError extends Error {
  public constructor(
    public readonly status: 400 | 401,
    public readonly error: OAuthErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export interface IssuedServiceToken {
  access_token: string;
  issued_token_type: "urn:ietf:params:oauth:token-type:access_token";
  token_type: "Bearer";
  expires_in: number;
  scope: string;
}

export interface ServiceTokenRequest {
  /** The authenticated calling service. */
  client: string;
  grant: "client_credentials" | "token_exchange";
  audience: string;
  scopes: readonly string[];
  /** Null requests a tenantless platform-level token. */
  tenantId: string | null;
  subjectToken?: string;
}

type SubjectType = "CUSTOMER" | "ADMINISTRATOR";
type SessionScope = "TENANT" | "PLATFORM";

interface VerifiedSubject {
  id: string;
  type: SubjectType;
  sessionId: string;
  scope: SessionScope;
  tenantId: string | null;
  expiresAt: number;
  act?: unknown;
}

export interface SubjectSessions {
  introspect(token: string, audience?: string): Promise<object>;
  sessionActive(input: {
    tenantId: string | null;
    scope: SessionScope;
    sessionId: string;
    subjectId: string;
    subjectType: SubjectType;
  }): Promise<boolean>;
}

/** User access tokens are issued to a BFF audience; only that BFF may exchange them. */
const userTokenAudienceByClient: Readonly<Record<string, string>> = {
  "parc-mobile-bff": "mobile-bff",
  "parc-admin-bff": "admin-bff",
};
const introspection = z.object({
  active: z.literal(true),
  subject: z.string().min(1),
  tenant_id: z.string().uuid().nullable(),
  subject_type: z.enum(["CUSTOMER", "ADMINISTRATOR"]),
  scope: z.enum(["TENANT", "PLATFORM"]),
  session_id: z.string().uuid(),
});
const delegatedClaims = z.object({
  sub: z.string().min(1),
  aud: z.string(),
  tenant_id: z.string().uuid().nullable(),
  subject_type: z.enum(["CUSTOMER", "ADMINISTRATOR"]),
  subject_scope: z.enum(["TENANT", "PLATFORM"]),
  session_id: z.string().uuid(),
  exp: z.number().int(),
  act: z.object({ sub: z.string() }).passthrough(),
});

const maxLifetimeSeconds = 300;
const selfClient = "parc-auth-customer";

/**
 * Issues short-lived, audience-bound service and delegated access tokens after
 * verifying the caller, its policy, the tenant, the user and the user's
 * entitlement to every requested scope.
 */
export class ServiceTokenService implements ServiceAuthorization {
  private readonly tenantStatus = new Map<
    string,
    { active: boolean; until: number }
  >();
  private readonly selfTokens = new Map<
    string,
    { header: string; expiresAt: number }
  >();

  public constructor(
    private readonly dependencies: {
      keys: JwtKeyRing;
      issuer: string;
      catalogue: ScopeCatalogue;
      tenants: TenantStatusReader;
      administrators: Pick<
        AdministratorTenantAdminClient,
        "getAdministratorAuthorization"
      >;
      sessions: SubjectSessions;
      now?: () => number;
      tenantCacheMs?: number;
    },
  ) {}

  public async issue(
    request: ServiceTokenRequest,
  ): Promise<IssuedServiceToken> {
    this.checkPolicy(request);
    if (request.tenantId !== null)
      await this.requireActiveTenant(request.tenantId);
    if (request.grant === "client_credentials")
      return this.sign({
        sub: request.client,
        client: request.client,
        audience: request.audience,
        tenantId: request.tenantId,
        scopes: request.scopes,
        expiresAt: this.now() + maxLifetimeSeconds,
      });

    if (!request.subjectToken)
      throw new OAuthError(400, "invalid_request", "subject_token is required");
    const subject = await this.verifySubject(
      request.subjectToken,
      request.client,
    );
    this.checkSubjectTenant(subject, request.tenantId);
    await this.checkEntitlement(subject, request.scopes);
    return this.sign({
      sub: subject.id,
      client: request.client,
      audience: request.audience,
      tenantId: request.tenantId,
      scopes: request.scopes,
      expiresAt: Math.min(this.now() + maxLifetimeSeconds, subject.expiresAt),
      delegation: {
        subjectType: subject.type,
        sessionId: subject.sessionId,
        subjectScope: subject.scope,
        act:
          subject.act === undefined
            ? { sub: request.client }
            : { sub: request.client, act: subject.act },
      },
    });
  }

  /**
   * Auth's own outbound calls: a service-only token for `parc-auth-customer`,
   * signed locally under the same policy. The tenant status check is skipped
   * because Tenant Admin itself is the callee for status reads.
   */
  public async authorization(input: {
    audience: string;
    scopes: readonly string[];
    tenantId: string | null;
  }): Promise<string> {
    const request: ServiceTokenRequest = {
      client: selfClient,
      grant: "client_credentials",
      audience: input.audience,
      scopes: [...new Set(input.scopes)].sort(),
      tenantId: input.tenantId,
    };
    const key = `${request.audience}|${request.tenantId ?? "platform"}|${request.scopes.join(" ")}`;
    const cached = this.selfTokens.get(key);
    if (cached && cached.expiresAt - 30 > this.now()) return cached.header;
    this.checkPolicy(request);
    const issued = await this.sign({
      sub: selfClient,
      client: selfClient,
      audience: request.audience,
      tenantId: request.tenantId,
      scopes: request.scopes,
      expiresAt: this.now() + maxLifetimeSeconds,
    });
    const header = `Bearer ${issued.access_token}`;
    if (this.selfTokens.size >= 1_000) this.selfTokens.clear();
    this.selfTokens.set(key, {
      header,
      expiresAt: this.now() + issued.expires_in,
    });
    return header;
  }

  private checkPolicy(request: ServiceTokenRequest): void {
    const { catalogue } = this.dependencies;
    const policy = catalogue.clients[request.client];
    if (!policy)
      throw new OAuthError(401, "invalid_client", "Client is not registered");
    if (request.audience === request.client)
      throw new OAuthError(
        400,
        "invalid_request",
        "A service cannot target itself",
      );
    if (
      request.scopes.length === 0 ||
      new Set(request.scopes).size !== request.scopes.length
    )
      throw new OAuthError(
        400,
        "invalid_scope",
        "Scopes must be distinct and non-empty",
      );
    const allowed =
      request.grant === "client_credentials"
        ? policy.service
        : policy.delegated;
    for (const name of request.scopes) {
      const scope = catalogue.scopes[name];
      if (
        scope?.audience !== request.audience ||
        !allowed.includes(name) ||
        (request.grant === "client_credentials"
          ? !scope.service
          : Object.keys(scope.delegated).length === 0) ||
        (request.tenantId === null && scope.platform !== true)
      )
        throw new OAuthError(
          400,
          "invalid_scope",
          `Scope ${name} is not permitted for this client, audience and grant`,
        );
    }
  }

  private async requireActiveTenant(tenantId: string): Promise<void> {
    const now = (this.dependencies.now ?? Date.now)();
    const cached = this.tenantStatus.get(tenantId);
    let active = cached && cached.until > now ? cached.active : undefined;
    if (active === undefined) {
      try {
        active =
          (await this.dependencies.tenants.getTenantStatus(tenantId)) ===
          "ACTIVE";
      } catch {
        active = false;
      }
      if (this.tenantStatus.size >= 10_000) this.tenantStatus.clear();
      this.tenantStatus.set(tenantId, {
        active,
        until: now + (this.dependencies.tenantCacheMs ?? 30_000),
      });
    }
    if (!active)
      throw new OAuthError(400, "invalid_grant", "Tenant is not active");
  }

  private async verifySubject(
    token: string,
    client: string,
  ): Promise<VerifiedSubject> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(
        token,
        (header) => {
          const key = header.kid
            ? this.dependencies.keys.publicKeys.get(header.kid)
            : undefined;
          if (!key) throw new Error("Unknown key");
          return key;
        },
        { issuer: this.dependencies.issuer, algorithms: ["RS256"] },
      ));
    } catch {
      throw new OAuthError(400, "invalid_grant", "subject_token is invalid");
    }

    if (payload.token_use === "delegated") {
      const claims = delegatedClaims.safeParse(payload);
      // A delegated token may only be exchanged by the service it was issued to.
      if (!claims.success || claims.data.aud !== client)
        throw new OAuthError(
          400,
          "invalid_grant",
          "subject_token was not issued to this client",
        );
      const subject = claims.data;
      const sessionTenant =
        subject.subject_scope === "PLATFORM" ? null : subject.tenant_id;
      if (
        !(await this.dependencies.sessions.sessionActive({
          tenantId: sessionTenant,
          scope: subject.subject_scope,
          sessionId: subject.session_id,
          subjectId: subject.sub,
          subjectType: subject.subject_type,
        }))
      )
        throw new OAuthError(
          400,
          "invalid_grant",
          "The user session is no longer active",
        );
      return {
        id: subject.sub,
        type: subject.subject_type,
        sessionId: subject.session_id,
        scope: subject.subject_scope,
        tenantId: sessionTenant,
        expiresAt: subject.exp,
        act: subject.act,
      };
    }
    if (payload.token_use !== undefined)
      throw new OAuthError(
        400,
        "invalid_grant",
        "A service token cannot be a subject",
      );

    const audience = userTokenAudienceByClient[client];
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audience || !audiences.includes(audience))
      throw new OAuthError(
        400,
        "invalid_grant",
        "subject_token was not issued to this client",
      );
    const state = introspection.safeParse(
      await this.dependencies.sessions.introspect(token, audience),
    );
    if (!state.success)
      throw new OAuthError(
        400,
        "invalid_grant",
        "The user session is no longer active",
      );
    return {
      id: state.data.subject,
      type: state.data.subject_type,
      sessionId: state.data.session_id,
      scope: state.data.scope,
      tenantId: state.data.tenant_id,
      expiresAt: payload.exp ?? 0,
    };
  }

  private checkSubjectTenant(
    subject: VerifiedSubject,
    tenantId: string | null,
  ): void {
    const permitted =
      subject.scope === "PLATFORM"
        ? subject.type === "ADMINISTRATOR"
        : tenantId !== null && subject.tenantId === tenantId;
    if (!permitted)
      throw new OAuthError(
        400,
        "invalid_grant",
        "The user does not belong to the requested tenant",
      );
  }

  private async checkEntitlement(
    subject: VerifiedSubject,
    scopes: readonly string[],
  ): Promise<void> {
    const rules = scopes.map(
      (name) =>
        [
          name,
          this.dependencies.catalogue.scopes[name]?.delegated[subject.type],
        ] as const,
    );
    const denied = rules.find(([, rule]) => rule === undefined);
    if (denied)
      throw new OAuthError(
        400,
        "invalid_scope",
        `Scope ${denied[0]} cannot be delegated by this user`,
      );
    const required = rules.filter(
      (entry): entry is readonly [string, string] =>
        typeof entry[1] === "string",
    );
    if (required.length === 0) return;
    // Permissions are read live from Tenant Admin, never from the token.
    const { permissions } =
      await this.dependencies.administrators.getAdministratorAuthorization(
        subject.id,
      );
    const missing = required.find(
      ([, permission]) => !permissions.includes(permission),
    );
    if (missing)
      throw new OAuthError(
        400,
        "invalid_scope",
        `The administrator lacks the permission for ${missing[0]}`,
      );
  }

  private async sign(input: {
    sub: string;
    client: string;
    audience: string;
    tenantId: string | null;
    scopes: readonly string[];
    expiresAt: number;
    delegation?: {
      subjectType: SubjectType;
      sessionId: string;
      subjectScope: SessionScope;
      act: object;
    };
  }): Promise<IssuedServiceToken> {
    const issuedAt = this.now();
    const lifetime = input.expiresAt - issuedAt;
    if (lifetime < 1)
      throw new OAuthError(400, "invalid_grant", "subject_token has expired");
    const scope = [...input.scopes].sort().join(" ");
    const accessToken = await new SignJWT({
      client_id: input.client,
      token_use: input.delegation ? "delegated" : "service",
      tenant_id: input.tenantId,
      scope,
      ...(input.delegation
        ? {
            subject_type: input.delegation.subjectType,
            session_id: input.delegation.sessionId,
            subject_scope: input.delegation.subjectScope,
            act: input.delegation.act,
          }
        : {}),
    })
      .setProtectedHeader({
        alg: "RS256",
        kid: this.dependencies.keys.activeKid,
        typ: "JWT",
      })
      .setIssuer(this.dependencies.issuer)
      .setAudience(input.audience)
      .setSubject(input.sub)
      .setJti(randomUUID())
      .setIssuedAt(issuedAt)
      .setExpirationTime(input.expiresAt)
      .sign(this.dependencies.keys.privateKey);
    return {
      access_token: accessToken,
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: lifetime,
      scope,
    };
  }

  private now(): number {
    return Math.floor((this.dependencies.now ?? Date.now)() / 1000);
  }
}
