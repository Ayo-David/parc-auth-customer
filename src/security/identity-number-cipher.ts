import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export interface EncryptedIdentityNumber {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyId: string;
}

/** Who the number belongs to; bound into the ciphertext as associated data. */
export interface IdentityNumberOwner {
  tenantId: string;
  customerId: string;
  identityType: "BVN" | "NIN";
}

/**
 * AES-256-GCM for stored identity numbers (BVN). The owner is authenticated
 * as associated data, so a ciphertext copied to another customer's row fails
 * to decrypt. Keys are addressed by id so the active key can be rotated
 * while older rows still decrypt.
 */
export class IdentityNumberCipher {
  private readonly keys: ReadonlyMap<string, Buffer>;

  public constructor(
    private readonly activeKeyId: string,
    keys: Record<string, string>,
  ) {
    const decoded = new Map<string, Buffer>();
    for (const [id, base64] of Object.entries(keys)) {
      const key = Buffer.from(base64, "base64");
      if (key.length !== 32)
        throw new Error(`Identity number key ${id} must be 32 bytes`);
      decoded.set(id, key);
    }
    if (!decoded.has(activeKeyId))
      throw new Error("Active identity number key is not configured");
    this.keys = decoded;
  }

  public encrypt(
    value: string,
    owner: IdentityNumberOwner,
  ): EncryptedIdentityNumber {
    const iv = randomBytes(12);
    const cipher = createCipheriv(
      "aes-256-gcm",
      this.key(this.activeKeyId),
      iv,
    );
    cipher.setAAD(associatedData(owner));
    const ciphertext = Buffer.concat([
      cipher.update(value, "utf8"),
      cipher.final(),
    ]);
    return {
      ciphertext: ciphertext.toString("base64"),
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      keyId: this.activeKeyId,
    };
  }

  public decrypt(
    encrypted: EncryptedIdentityNumber,
    owner: IdentityNumberOwner,
  ): string {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key(encrypted.keyId),
      Buffer.from(encrypted.iv, "base64"),
    );
    decipher.setAAD(associatedData(owner));
    decipher.setAuthTag(Buffer.from(encrypted.authTag, "base64"));
    return Buffer.concat([
      decipher.update(Buffer.from(encrypted.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8");
  }

  private key(id: string): Buffer {
    const key = this.keys.get(id);
    if (!key) throw new Error(`Identity number key ${id} is not configured`);
    return key;
  }
}

function associatedData(owner: IdentityNumberOwner): Buffer {
  return Buffer.from(
    `${owner.tenantId}:${owner.customerId}:${owner.identityType}`,
    "utf8",
  );
}
