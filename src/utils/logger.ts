import pino, { type Logger } from "pino";
import type { AppConfig } from "../config/env.js";

const redactedPaths = [
  "req.headers.authorization",
  "req.headers.cookie",
  "req.body.password",
  "req.body.pin",
  "req.body.otp",
  "req.body.token",
  "req.body.refresh_token",
  "req.body.bvn",
  "req.body.nin",
  "req.body.identity_value",
  "res.headers.set-cookie",
];

export function createLogger(config: AppConfig): Logger {
  return pino({
    level: config.LOG_LEVEL,
    base: { service: config.SERVICE_NAME, version: config.SERVICE_VERSION },
    redact: { paths: redactedPaths, censor: "[REDACTED]" },
  });
}
