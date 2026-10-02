import { randomUUID } from "node:crypto";
import { exportSPKI, generateKeyPair, SignJWT } from "jose";
import {
  ClientAssertionVerifier,
  ClientAuthenticationError,
} from "../../src/security/client-assertion-verifier.js";
import { MemoryRateLimiter } from "../../src/security/rate-limiter.js";

const issuer = "https://auth.parc.invalid";
type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
let lending: KeyPair;
let verifier: ClientAssertionVerifier;

beforeAll(async () => {
  lending = await generateKeyPair("ES256", { extractable: true });
  verifier = await ClientAssertionVerifier.create({
    clientKeysJson: JSON.stringify({
      "parc-lending": {
        "lending-1": Buffer.from(await exportSPKI(lending.publicKey)).toString(
          "base64",
        ),
      },
    }),
    audience: issuer,
    replay: new MemoryRateLimiter(),
  });
});

function assertion(
  options: {
    client?: string;
    kid?: string;
    audience?: string;
    lifetime?: number;
    jti?: string;
    key?: KeyPair["privateKey"];
  } = {},
): Promise<string> {
  const client = options.client ?? "parc-lending";
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: options.kid ?? "lending-1" })
    .setIssuer(client)
    .setSubject(client)
    .setAudience(options.audience ?? issuer)
    .setJti(options.jti ?? randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + (options.lifetime ?? 60))
    .sign(options.key ?? lending.privateKey);
}

describe("private_key_jwt client assertions", () => {
  it("authenticates a registered client", async () => {
    await expect(verifier.verify(await assertion())).resolves.toBe(
      "parc-lending",
    );
  });

  it("rejects replayed assertions", async () => {
    const reused = await assertion({ jti: randomUUID() });
    await verifier.verify(reused);
    await expect(verifier.verify(reused)).rejects.toBeInstanceOf(
      ClientAuthenticationError,
    );
  });

  it("rejects unknown clients, unknown keys, wrong audiences, long lifetimes and foreign keys", async () => {
    const foreign = await generateKeyPair("ES256");
    for (const candidate of [
      await assertion({ client: "parc-unknown" }),
      await assertion({ kid: "lending-2" }),
      await assertion({ audience: "https://elsewhere.invalid" }),
      await assertion({ lifetime: 600 }),
      await assertion({ key: foreign.privateKey }),
      "not-a-jwt",
    ])
      await expect(verifier.verify(candidate)).rejects.toBeInstanceOf(
        ClientAuthenticationError,
      );
  });
});
