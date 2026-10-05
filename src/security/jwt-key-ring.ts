import { exportJWK, generateKeyPair, importPKCS8, importSPKI } from "jose";

type PrivateJwtKey = Awaited<ReturnType<typeof importPKCS8>>;
type PublicJwtKey = Awaited<ReturnType<typeof importSPKI>>;

export interface JwtKeyRing {
  activeKid: string;
  privateKey: PrivateJwtKey;
  publicKeys: ReadonlyMap<string, PublicJwtKey>;
}

export async function publicJwks(
  keyRing: JwtKeyRing,
): Promise<{ keys: object[] }> {
  return {
    keys: await Promise.all(
      [...keyRing.publicKeys].map(async ([kid, key]) => ({
        ...(await exportJWK(key)),
        kid,
        use: "sig",
        alg: "RS256",
      })),
    ),
  };
}

export async function createJwtKeyRing(input: {
  activeKid: string;
  privateKeyBase64?: string;
  publicKeysJson?: string;
}): Promise<JwtKeyRing> {
  if (input.privateKeyBase64 && input.publicKeysJson) {
    const privateKey = await importPKCS8(
      Buffer.from(input.privateKeyBase64, "base64").toString("utf8"),
      "RS256",
    );
    const encodedPublicKeys = JSON.parse(input.publicKeysJson) as Record<
      string,
      string
    >;
    const publicKeys = new Map<string, PublicJwtKey>();
    for (const [kid, encoded] of Object.entries(encodedPublicKeys))
      publicKeys.set(
        kid,
        await importSPKI(
          Buffer.from(encoded, "base64").toString("utf8"),
          "RS256",
        ),
      );
    if (!publicKeys.has(input.activeKid))
      throw new Error("JWT public key set does not contain JWT_ACTIVE_KID");
    return { activeKid: input.activeKid, privateKey, publicKeys };
  }
  const generated = await generateKeyPair("RS256", { extractable: false });
  return {
    activeKid: input.activeKid,
    privateKey: generated.privateKey,
    publicKeys: new Map([[input.activeKid, generated.publicKey]]),
  };
}
