import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import type { RedisClientType } from "redis";

export interface OtpSecretStore {
  put(challengeId: string, code: string, ttlSeconds: number): Promise<void>;
  take(challengeId: string): Promise<string | undefined>;
  delete(challengeId: string): Promise<void>;
}

function encryptionKey(secret: string): Buffer {
  return createHash("sha256").update(secret).digest();
}

function encrypt(value: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString(
    "base64url",
  );
}

function decrypt(value: string, key: Buffer): string {
  const payload = Buffer.from(value, "base64url");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    payload.subarray(0, 12),
  );
  decipher.setAuthTag(payload.subarray(12, 28));
  return Buffer.concat([
    decipher.update(payload.subarray(28)),
    decipher.final(),
  ]).toString("utf8");
}

export class RedisOtpSecretStore implements OtpSecretStore {
  private readonly key: Buffer;
  public constructor(
    private readonly redis: RedisClientType,
    secret: string,
  ) {
    this.key = encryptionKey(secret);
  }
  public async put(
    challengeId: string,
    code: string,
    ttlSeconds: number,
  ): Promise<void> {
    await this.redis.set(`auth:otp:${challengeId}`, encrypt(code, this.key), {
      EX: ttlSeconds,
    });
  }
  public async take(challengeId: string): Promise<string | undefined> {
    const value = await this.redis.get(`auth:otp:${challengeId}`);
    return value ? decrypt(value, this.key) : undefined;
  }
  public async delete(challengeId: string): Promise<void> {
    await this.redis.del(`auth:otp:${challengeId}`);
  }
}

export class MemoryOtpSecretStore implements OtpSecretStore {
  private readonly values = new Map<
    string,
    { code: string; expiresAt: number }
  >();
  public put(
    challengeId: string,
    code: string,
    ttlSeconds: number,
  ): Promise<void> {
    this.values.set(challengeId, {
      code,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
    return Promise.resolve();
  }
  public take(challengeId: string): Promise<string | undefined> {
    const value = this.values.get(challengeId);
    if (!value || value.expiresAt <= Date.now()) {
      this.values.delete(challengeId);
      return Promise.resolve(undefined);
    }
    return Promise.resolve(value.code);
  }
  public delete(challengeId: string): Promise<void> {
    this.values.delete(challengeId);
    return Promise.resolve();
  }
}
