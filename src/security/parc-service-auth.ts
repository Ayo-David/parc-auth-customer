/**
 * parc-service-auth v1
 *
 * Shared service-to-service authentication for Parc services. Keep this file
 * byte-identical in every repository: cross-repository imports are not
 * allowed, so each service carries its own copy. The token contract is
 * `parc-contracts/schemas/security/service-access-token.v1.json` and scopes are
 * defined in `parc-contracts/security/scopes.v1.json`.
 *
 * - `createParcAuth` validates inbound `Authorization: Bearer` tokens issued by
 *   Auth & Customer and exposes a typed principal. Endpoint permissions stay
 *   in each domain service as `require({ scopes, kinds, subjectTypes, actors })`.
 * - `ParcTokenClient` obtains outbound tokens. During a delegated request it
 *   exchanges the inbound token so the user and acting chain are preserved;
 *   otherwise it requests a service-only token.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, randomUUID } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import {
  createRemoteJWKSet,
  importPKCS8,
  jwtVerify,
  SignJWT,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";

export type TokenUse = "service" | "delegated";
export type SubjectType = "CUSTOMER" | "ADMINISTRATOR";

export interface ParcPrincipal {
  kind: TokenUse;
  /**
   * Null only for platform-level operations, and only where the service sets
   * `allowPlatformTenant`.
   */
  tenantId: string | null;
  scopes: ReadonlySet<string>;
  /** The immediate calling service (`client_id`). */
  client: string;
  /** Acting services, immediate caller first. Empty for service tokens. */
  actors: readonly string[];
  subject?: { id: string; type: SubjectType; sessionId: string };
  token: string;
  expiresAt: number;
}

export interface AccessPolicy {
  /** Every listed scope is required. */
  scopes: readonly string[];
  /** Accepted token kinds; both when omitted. */
  kinds?: readonly TokenUse[];
  /** Accepted user types for delegated tokens; any when omitted. */
  subjectTypes?: readonly SubjectType[];
  /** Accepted immediate callers (`client_id`); any when omitted. */
  actors?: readonly string[];
}

export class ParcAuthError extends Error {
  public constructor(
    public readonly status: 401 | 403,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ParcAuthError";
  }
}

declare module "express-serve-static-core" {
  interface Request {
    parcPrincipal?: ParcPrincipal;
  }
}

const requestContext = new AsyncLocalStorage<ParcPrincipal | undefined>();
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const servicePattern = /^parc-[a-z0-9-]+$/;
const scopePattern = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/;

/** The principal of the request currently being handled, if any. */
export function currentPrincipal(): ParcPrincipal | undefined {
  return requestContext.getStore();
}

/** Runs work outside any inbound request so outbound calls are service-only. */
export function runAsService<T>(work: () => T): T {
  return requestContext.run(undefined, work);
}

export function principalOf(request: Request): ParcPrincipal {
  if (!request.parcPrincipal)
    throw new ParcAuthError(401, "UNAUTHORIZED", "Authentication required");
  return request.parcPrincipal;
}

export function authorize(
  principal: ParcPrincipal,
  policy: AccessPolicy,
): void {
  if (policy.kinds && !policy.kinds.includes(principal.kind))
    throw new ParcAuthError(
      403,
      "TOKEN_KIND_FORBIDDEN",
      `A ${principal.kind} token is not accepted for this operation`,
    );
  if (
    principal.kind === "delegated" &&
    policy.subjectTypes &&
    (!principal.subject ||
      !policy.subjectTypes.includes(principal.subject.type))
  )
    throw new ParcAuthError(
      403,
      "SUBJECT_FORBIDDEN",
      "The delegated user type is not accepted for this operation",
    );
  if (policy.actors && !policy.actors.includes(principal.client))
    throw new ParcAuthError(
      403,
      "CALLER_FORBIDDEN",
      "The calling service is not permitted for this operation",
    );
  const missing = policy.scopes.filter((scope) => !principal.scopes.has(scope));
  if (missing.length > 0)
    throw new ParcAuthError(
      403,
      "INSUFFICIENT_SCOPE",
      `Missing required scope: ${missing.join(" ")}`,
    );
}

export interface ParcAuthOptions {
  issuer: string;
  /** This service's name; tokens must be issued for it. */
  audience: string;
  jwksUrl?: string;
  /** Overrides `jwksUrl`, e.g. Auth verifying with its own key ring. */
  keys?: JWTVerifyGetKey;
  /**
   * Accept tenantless platform-level tokens: service tokens and delegated
   * platform-administrator tokens. Routes must still require platform scopes.
   */
  allowPlatformTenant?: boolean;
  algorithms?: string[];
}

export interface ParcAuth {
  verify(token: string): Promise<ParcPrincipal>;
  /** Validates the bearer token and records the principal and request context. */
  authenticate(): RequestHandler;
  /** `authenticate()` followed by an endpoint access policy. */
  require(policy: AccessPolicy): RequestHandler;
}

export function createParcAuth(options: ParcAuthOptions): ParcAuth {
  const keys = options.keys ?? remoteKeys(options.jwksUrl);

  async function verify(token: string): Promise<ParcPrincipal> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keys, {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: options.algorithms ?? ["RS256"],
        clockTolerance: 5,
        maxTokenAge: "10m",
        requiredClaims: ["sub", "jti", "iat", "exp"],
      }));
    } catch {
      throw new ParcAuthError(401, "INVALID_TOKEN", "Access token is invalid");
    }
    return principalFromClaims(payload, token, options.allowPlatformTenant);
  }

  function authenticate(): RequestHandler {
    return (request, response, next) => {
      void (async () => {
        const token = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(
          request.header("authorization") ?? "",
        )?.[1];
        if (token === undefined)
          throw new ParcAuthError(
            401,
            "UNAUTHORIZED",
            "Bearer access token required",
          );
        const principal = await verify(token);
        const tenantHeader = request.header("x-tenant-id");
        if (tenantHeader !== undefined && tenantHeader !== principal.tenantId)
          throw new ParcAuthError(
            403,
            "TENANT_MISMATCH",
            "Token tenant does not match X-Tenant-Id",
          );
        const callerHeader = request.header("x-calling-service");
        if (callerHeader !== undefined && callerHeader !== principal.client)
          throw new ParcAuthError(
            403,
            "CALLER_MISMATCH",
            "X-Calling-Service does not match the token client",
          );
        request.parcPrincipal = principal;
        return principal;
      })().then(
        (principal) => {
          requestContext.run(principal, next);
        },
        (error: unknown) => {
          respond(response, options.audience, error, next);
        },
      );
    };
  }

  function requirePolicy(policy: AccessPolicy): RequestHandler {
    const authenticateRequest = authenticate();
    return (request, response, next) => {
      authenticateRequest(request, response, (error?: unknown) => {
        if (error !== undefined) {
          next(error);
          return;
        }
        try {
          authorize(principalOf(request), policy);
        } catch (failure) {
          respond(response, options.audience, failure, next);
          return;
        }
        next();
      });
    };
  }

  return { verify, authenticate, require: requirePolicy };
}

function remoteKeys(jwksUrl: string | undefined): JWTVerifyGetKey {
  if (!jwksUrl) throw new Error("parc-service-auth requires jwksUrl or keys");
  return createRemoteJWKSet(new URL(jwksUrl), {
    cooldownDuration: 30_000,
    timeoutDuration: 5_000,
  });
}

/** Claims read from a verified token; values are untrusted until checked. */
interface TokenClaims {
  sub?: unknown;
  exp?: number;
  token_use?: unknown;
  client_id?: unknown;
  scope?: unknown;
  tenant_id?: unknown;
  subject_type?: unknown;
  session_id?: unknown;
  act?: unknown;
}

function principalFromClaims(
  payload: JWTPayload,
  token: string,
  allowPlatformTenant = false,
): ParcPrincipal {
  const claims: TokenClaims = payload;
  const invalid = (message: string) =>
    new ParcAuthError(401, "INVALID_TOKEN", message);
  const kind = claims.token_use;
  if (kind !== "service" && kind !== "delegated")
    throw invalid("Token is not a service or delegated token");
  const client = claims.client_id;
  if (typeof client !== "string" || !servicePattern.test(client))
    throw invalid("Token client is invalid");
  if (typeof claims.scope !== "string") throw invalid("Token scope is missing");
  const scopes = claims.scope.split(" ");
  if (scopes.some((scope) => !scopePattern.test(scope)))
    throw invalid("Token scope is invalid");
  const tenantId = claims.tenant_id;
  if (
    tenantId !== null &&
    (typeof tenantId !== "string" || !uuidPattern.test(tenantId))
  )
    throw invalid("Token tenant is invalid");
  const base = {
    tenantId,
    scopes: new Set(scopes),
    client,
    token,
    expiresAt: claims.exp ?? 0,
  };
  if (kind === "service") {
    if (claims.sub !== client || claims.act !== undefined)
      throw invalid("Service token claims are inconsistent");
    if (tenantId === null && !allowPlatformTenant)
      throw invalid("A tenant-bound token is required");
    return { ...base, kind, actors: [] };
  }
  const actors = actorChain(claims.act);
  const subjectType = claims.subject_type;
  const sessionId = claims.session_id;
  if (
    actors[0] !== client ||
    (subjectType !== "CUSTOMER" && subjectType !== "ADMINISTRATOR") ||
    typeof sessionId !== "string" ||
    !uuidPattern.test(sessionId) ||
    typeof claims.sub !== "string"
  )
    throw invalid("Delegated token claims are inconsistent");
  if (
    tenantId === null &&
    (!allowPlatformTenant || subjectType !== "ADMINISTRATOR")
  )
    throw invalid("A tenant-bound token is required");
  return {
    ...base,
    kind,
    actors,
    subject: { id: claims.sub, type: subjectType, sessionId },
  };
}

function actorChain(value: unknown): string[] {
  const chain: string[] = [];
  let current = value;
  while (current !== undefined) {
    if (
      typeof current !== "object" ||
      current === null ||
      typeof (current as { sub?: unknown }).sub !== "string" ||
      !servicePattern.test((current as { sub: string }).sub) ||
      chain.length >= 8
    )
      throw new ParcAuthError(401, "INVALID_TOKEN", "Token actor is invalid");
    chain.push((current as { sub: string }).sub);
    current = (current as { act?: unknown }).act;
  }
  return chain;
}

function respond(
  response: Response,
  realm: string,
  error: unknown,
  next: NextFunction,
): void {
  if (!(error instanceof ParcAuthError)) {
    next(error);
    return;
  }
  if (error.status === 401)
    response.setHeader(
      "WWW-Authenticate",
      `Bearer realm="${realm}", error="invalid_token"`,
    );
  else if (error.code === "INSUFFICIENT_SCOPE")
    response.setHeader(
      "WWW-Authenticate",
      `Bearer realm="${realm}", error="insufficient_scope"`,
    );
  response
    .status(error.status)
    .json({ code: error.code, message: error.message });
}

export class ParcTokenError extends Error {
  public constructor(
    public readonly status: number,
    public readonly error: string,
  ) {
    super(`Service token request failed (${String(status)} ${error})`);
    this.name = "ParcTokenError";
  }
}

export interface TokenRequest {
  audience: string;
  scopes: readonly string[];
  /** Null requests a tenantless platform-level token. */
  tenantId: string | null;
  /**
   * `auto` (default) delegates when handling a delegated request and otherwise
   * requests a service-only token.
   */
  mode?: "auto" | "service" | "delegated";
  /** Explicit subject, e.g. a BFF exchanging the user's access token. */
  subjectToken?: string;
}

type SigningKey = Awaited<ReturnType<typeof importPKCS8>>;

export interface ParcTokenClientOptions {
  /** Auth & Customer token endpoint URL. */
  tokenUrl: string;
  /** Auth issuer; the client assertion audience. */
  issuer: string;
  clientId: string;
  keyId: string;
  privateKey: SigningKey;
  fetch?: typeof fetch;
  timeoutMs?: number;
  now?: () => number;
}

export class ParcTokenClient {
  private readonly cache = new Map<
    string,
    { token: string; expiresAt: number }
  >();

  public constructor(private readonly options: ParcTokenClientOptions) {}

  /** Builds a client from a base64-encoded PKCS#8 ES256 private key. */
  public static async fromBase64Key(
    options: Omit<ParcTokenClientOptions, "privateKey"> & {
      privateKeyBase64: string;
    },
  ): Promise<ParcTokenClient> {
    const { privateKeyBase64, ...rest } = options;
    return new ParcTokenClient({
      ...rest,
      privateKey: await importPKCS8(
        Buffer.from(privateKeyBase64, "base64").toString("utf8"),
        "ES256",
      ),
    });
  }

  /** Returns an `Authorization` header value. */
  public async authorization(request: TokenRequest): Promise<string> {
    return `Bearer ${await this.token(request)}`;
  }

  public async token(request: TokenRequest): Promise<string> {
    const subjectToken = this.subjectToken(request);
    const scopes = [...new Set(request.scopes)].sort();
    const key = [
      subjectToken === undefined ? "service" : "delegated",
      request.audience,
      request.tenantId ?? "platform",
      scopes.join(" "),
      subjectToken === undefined
        ? ""
        : createHash("sha256").update(subjectToken).digest("hex"),
    ].join("|");
    const now = this.now();
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt - 30 > now) return cached.token;

    const body = new URLSearchParams({
      grant_type:
        subjectToken === undefined
          ? "client_credentials"
          : "urn:ietf:params:oauth:grant-type:token-exchange",
      client_assertion_type:
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await this.assertion(),
      audience: request.audience,
      scope: scopes.join(" "),
      tenant_id: request.tenantId ?? "platform",
    });
    if (subjectToken !== undefined) {
      body.set("subject_token", subjectToken);
      body.set(
        "subject_token_type",
        "urn:ietf:params:oauth:token-type:access_token",
      );
    }
    const response = await (this.options.fetch ?? fetch)(
      this.options.tokenUrl,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 5_000),
      },
    );
    const result = (await response.json().catch(() => ({}))) as {
      access_token?: unknown;
      expires_in?: unknown;
      error?: unknown;
    };
    if (
      !response.ok ||
      typeof result.access_token !== "string" ||
      typeof result.expires_in !== "number"
    )
      throw new ParcTokenError(
        response.status,
        typeof result.error === "string" ? result.error : "invalid_response",
      );
    if (this.cache.size >= 1_000) this.cache.clear();
    this.cache.set(key, {
      token: result.access_token,
      expiresAt: now + result.expires_in,
    });
    return result.access_token;
  }

  private subjectToken(request: TokenRequest): string | undefined {
    if (request.subjectToken !== undefined) return request.subjectToken;
    if (request.mode === "service") return undefined;
    const principal = currentPrincipal();
    if (principal?.kind === "delegated") return principal.token;
    if (request.mode === "delegated")
      throw new ParcTokenError(0, "no_delegated_subject");
    return undefined;
  }

  private assertion(): Promise<string> {
    return new SignJWT({})
      .setProtectedHeader({ alg: "ES256", kid: this.options.keyId, typ: "JWT" })
      .setIssuer(this.options.clientId)
      .setSubject(this.options.clientId)
      .setAudience(this.options.issuer)
      .setJti(randomUUID())
      .setIssuedAt()
      .setExpirationTime("60s")
      .sign(this.options.privateKey);
  }

  private now(): number {
    return Math.floor((this.options.now ?? Date.now)() / 1000);
  }
}
