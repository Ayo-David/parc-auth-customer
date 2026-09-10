import type { RedisClientType } from "redis";

export interface RateLimiter {
  consume(key: string, limit: number, windowSeconds: number): Promise<boolean>;
}

export class RedisRateLimiter implements RateLimiter {
  public constructor(private readonly redis: RedisClientType) {}

  public async consume(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<boolean> {
    const count = await this.redis.incr(key);
    if (count === 1) await this.redis.expire(key, windowSeconds);
    return count <= limit;
  }
}

export class MemoryRateLimiter implements RateLimiter {
  private readonly entries = new Map<
    string,
    { count: number; expiresAt: number }
  >();

  public consume(
    key: string,
    limit: number,
    windowSeconds: number,
  ): Promise<boolean> {
    const now = Date.now();
    const existing = this.entries.get(key);
    const entry =
      !existing || existing.expiresAt <= now
        ? { count: 0, expiresAt: now + windowSeconds * 1000 }
        : existing;
    entry.count += 1;
    this.entries.set(key, entry);
    return Promise.resolve(entry.count <= limit);
  }
}
