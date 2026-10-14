/**
 * Prints the pending OTP for one challenge, for testing while SMS delivery is
 * unavailable. Reading does not consume the code. Only works with Redis-backed
 * OTP storage; memory-backed codes live inside the API process.
 *
 *   docker exec parc-auth-customer node dist/src/cli/read-otp.js <challenge_id>
 *   node --env-file=.env --import tsx src/cli/read-otp.ts <challenge_id>
 */
import { createClient } from "redis";
import { z } from "zod";
import { loadConfig } from "../config/env.js";
import { RedisOtpSecretStore } from "../security/otp-secret-store.js";

const challengeId = z.string().uuid().safeParse(process.argv[2]);
if (!challengeId.success) {
  console.error("Usage: read-otp <challenge_id>");
  process.exit(1);
}

const config = loadConfig();
if (config.RATE_LIMIT_STORE !== "redis") {
  console.error(
    "OTPs are only readable when RATE_LIMIT_STORE=redis; memory-backed codes stay inside the API process.",
  );
  process.exit(1);
}

const redis = createClient({ url: config.REDIS_URL });
await redis.connect();
try {
  const code = await new RedisOtpSecretStore(
    redis,
    config.CHALLENGE_HASH_SECRET,
  ).take(challengeId.data);
  if (!code) {
    console.error("No pending OTP for that challenge; it expired or was used.");
    process.exitCode = 1;
  } else {
    const ttl = await redis.ttl(`auth:otp:${challengeId.data}`);
    console.log(`${code} (expires in ${String(ttl)}s)`);
  }
} finally {
  await redis.quit();
}
