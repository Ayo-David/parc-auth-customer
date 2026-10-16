const probeKey = "parc-auth-customer:readiness:probe";

interface ExpiringWriter {
  set(
    key: string,
    value: string,
    mode: "EX",
    seconds: number,
  ): Promise<unknown>;
}

/**
 * PING succeeds against a read-only replica, but OTP, rate limiting and
 * client-assertion replay protection all write, so readiness must too.
 */
export async function checkRedisWritable(redis: ExpiringWriter): Promise<void> {
  await redis.set(probeKey, String(Date.now()), "EX", 30);
}
