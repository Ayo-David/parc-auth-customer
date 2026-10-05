import { decodeJwt, decodeProtectedHeader, importSPKI, jwtVerify } from "jose";
import { z } from "zod";
import type { RateLimiter } from "./rate-limiter.js";

type PublicKey = Awaited<ReturnType<typeof importSPKI>>;

/** `{ "<client-id>": { "<kid>": "<base64 SPKI PEM>" } }` */
export const serviceClientKeysSchema = z.record(
  z.string().regex(/^parc-[a-z0-9-]+$/),
  z.record(z.string().min(1).max(100), z.string().min(1)),
);

export class ClientAuthenticationError extends Error {}

/**
 * Verifies RFC 7523 `private_key_jwt` client assertions. Each service holds
 * only its own private key; Auth holds only registered public keys, so no
 * shared secret exists between services.
 */
export class ClientAssertionVerifier {
  private constructor(
    private readonly keys: ReadonlyMap<string, ReadonlyMap<string, PublicKey>>,
    private readonly audience: string,
    private readonly replay: RateLimiter,
  ) {}

  public static async create(input: {
    clientKeysJson: string;
    audience: string;
    replay: RateLimiter;
  }): Promise<ClientAssertionVerifier> {
    const parsed = serviceClientKeysSchema.parse(
      JSON.parse(input.clientKeysJson),
    );
    const keys = new Map<string, Map<string, PublicKey>>();
    for (const [client, entries] of Object.entries(parsed)) {
      const clientKeys = new Map<string, PublicKey>();
      for (const [kid, encoded] of Object.entries(entries))
        clientKeys.set(
          kid,
          await importSPKI(
            Buffer.from(encoded, "base64").toString("utf8"),
            "ES256",
          ),
        );
      keys.set(client, clientKeys);
    }
    return new ClientAssertionVerifier(keys, input.audience, input.replay);
  }

  public registered(client: string): boolean {
    return this.keys.has(client);
  }

  /** Returns the authenticated client ID. */
  public async verify(assertion: string): Promise<string> {
    let client: unknown;
    let kid: unknown;
    try {
      client = decodeJwt(assertion).iss;
      kid = decodeProtectedHeader(assertion).kid;
    } catch {
      throw new ClientAuthenticationError("Malformed client assertion");
    }
    const key =
      typeof client === "string" && typeof kid === "string"
        ? this.keys.get(client)?.get(kid)
        : undefined;
    if (!key || typeof client !== "string")
      throw new ClientAuthenticationError("Unknown client or key");
    let payload: { jti?: string; iat?: number; exp?: number };
    try {
      ({ payload } = await jwtVerify(assertion, key, {
        issuer: client,
        subject: client,
        audience: this.audience,
        algorithms: ["ES256"],
        clockTolerance: 5,
        maxTokenAge: "60s",
        requiredClaims: ["jti", "iat", "exp"],
      }));
    } catch {
      throw new ClientAuthenticationError("Invalid client assertion");
    }
    const { jti, iat, exp } = payload;
    if (jti === undefined || iat === undefined || exp === undefined)
      throw new ClientAuthenticationError("Client assertion claims missing");
    if (exp - iat > 60)
      throw new ClientAuthenticationError("Client assertion lifetime too long");
    if (
      !(await this.replay.consume(`client-assertion:${client}:${jti}`, 1, 120))
    )
      throw new ClientAuthenticationError("Client assertion was replayed");
    return client;
  }
}
