import { Redis, type RedisOptions } from "ioredis";
import type { AppConfig } from "../config/env.js";

type RedisConfig = Pick<
  AppConfig,
  | "SERVICE_NAME"
  | "REDIS_URL"
  | "REDIS_SENTINELS"
  | "REDIS_SENTINEL_MASTER_NAME"
  | "REDIS_SENTINEL_PASSWORD"
  | "REDIS_PASSWORD"
>;

/**
 * A demoted primary stays reachable but rejects writes; reconnecting makes
 * ioredis ask Sentinel for the current primary and resend the command.
 */
export function reconnectOnReadOnly(error: Error): 2 | false {
  return error.message.startsWith("READONLY") ? 2 : false;
}

export function redisOptions(config: RedisConfig): RedisOptions {
  const shared: RedisOptions = {
    connectionName: config.SERVICE_NAME,
    lazyConnect: true,
    reconnectOnError: reconnectOnReadOnly,
    retryStrategy: (attempt) => Math.min(attempt * 100, 2_000),
    // Bound how long a request waits during failover instead of hanging.
    maxRetriesPerRequest: 10,
  };
  if (config.REDIS_SENTINELS.length === 0) return shared;
  return {
    ...shared,
    sentinels: config.REDIS_SENTINELS,
    name: config.REDIS_SENTINEL_MASTER_NAME,
    role: "master",
    ...(config.REDIS_PASSWORD ? { password: config.REDIS_PASSWORD } : {}),
    ...(config.REDIS_SENTINEL_PASSWORD
      ? { sentinelPassword: config.REDIS_SENTINEL_PASSWORD }
      : {}),
    // Subscribes to +switch-master so a failover reconnects immediately.
    failoverDetector: true,
    sentinelRetryStrategy: (attempt) => Math.min(attempt * 100, 2_000),
  };
}

export function createRedis(config: RedisConfig): Redis {
  return config.REDIS_SENTINELS.length === 0
    ? new Redis(config.REDIS_URL, redisOptions(config))
    : new Redis(redisOptions(config));
}
