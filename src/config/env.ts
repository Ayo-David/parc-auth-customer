import { z } from "zod";

/** Provider base URL without a trailing slash, so paths join cleanly. */
const baseUrl = (fallback: string) =>
  z
    .string()
    .url()
    .default(fallback)
    .transform((value) => value.replace(/\/+$/, ""));

/** Development-only BVN encryption key; production refuses to start with it. */
const DEVELOPMENT_IDENTITY_NUMBER_KEY =
  "ZGV2ZWxvcG1lbnQtaWRlbnRpdHktbnVtYmVyLWtleSE=";
const DEVELOPMENT_IDENTITY_NUMBER_KEY_ID = "development-v1";

const environmentSchema = z
  .object({
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    HOST: z.string().min(1).default("0.0.0.0"),
    PORT: z.coerce.number().int().min(1).max(65_535).default(3001),
    LOG_LEVEL: z
      .enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"])
      .default("info"),
    SERVICE_NAME: z.string().min(1).default("parc-auth-customer"),
    SERVICE_VERSION: z.string().min(1).default("0.1.0"),
    SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
    DATABASE_URL: z.string().min(1).default("postgresql:///parc_auth_customer"),
    DATABASE_POOL_MIN: z.coerce.number().int().min(0).default(0),
    DATABASE_POOL_MAX: z.coerce.number().int().positive().default(10),
    TENANT_ADMIN_INTERNAL_URL: z
      .string()
      .url()
      .default("http://localhost:3002"),
    /**
     * Registered service clients for `private_key_jwt`:
     * `{ "<client-id>": { "<kid>": "<base64 SPKI PEM>" } }`. Public keys only.
     */
    SERVICE_CLIENT_KEYS_JSON: z.string().min(2).default("{}"),
    IDEMPOTENCY_HASH_SECRET: z
      .string()
      .min(32)
      .default("development-idempotency-secret-change-me"),
    CHALLENGE_HASH_SECRET: z
      .string()
      .min(32)
      .default("development-challenge-secret-change-me"),
    RATE_LIMIT_STORE: z.enum(["memory", "redis"]).default("memory"),
    REDIS_URL: z.string().url().default("redis://localhost:6379"),
    JWT_ISSUER: z.string().url().default("https://auth.parc.invalid"),
    JWT_ACTIVE_KID: z.string().min(1).default("development-ephemeral"),
    JWT_PRIVATE_KEY_BASE64: z.string().min(1).optional(),
    JWT_PUBLIC_KEYS_JSON: z.string().min(2).optional(),
    TOKEN_HASH_SECRET: z
      .string()
      .min(32)
      .default("development-token-hash-secret-change-me"),
    /** Providers are chosen per capability so identity and face checks can differ. */
    KYC_IDENTITY_PROVIDER: z.enum(["VERIFYME", "PREMBLY"]).default("PREMBLY"),
    KYC_FACE_PROVIDER: z.enum(["VERIFYME", "PREMBLY"]).default("PREMBLY"),
    PREMBLY_BASE_URL: baseUrl("https://api.prembly.com"),
    PREMBLY_API_KEY: z
      .string()
      .min(1)
      .default("development-prembly-key-change-me"),
    PREMBLY_APP_ID: z.string().min(1).optional(),
    PREMBLY_CONFIGURATION_VERSION: z.string().min(1).default("development-v1"),
    PREMBLY_TIMEOUT_MS: z.coerce.number().int().positive().default(20_000),
    PREMBLY_FACE_MATCH_THRESHOLD: z.coerce
      .number()
      .int()
      .min(70)
      .max(100)
      .default(80),
    PREMBLY_ALLOW_SANDBOX: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    PREMBLY_LIVENESS_MIN_PERCENT: z.coerce.number().min(0).max(100).default(90),
    PREMBLY_DEBUG_LOG: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    VERIFYME_BASE_URL: baseUrl("https://vapi.verifyme.ng"),
    VERIFYME_API_KEY: z
      .string()
      .min(1)
      .default("development-verifyme-key-change-me"),
    VERIFYME_CONFIGURATION_VERSION: z.string().min(1).default("development-v1"),
    VERIFYME_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),
    KYC_IDENTIFIER_HASH_SECRET: z
      .string()
      .min(32)
      .default("development-kyc-hash-secret-change-me"),
    KYC_IDENTIFIER_HASH_KEY_ID: z.string().min(1).default("development-v1"),
    KYC_RESULT_SIGNING_SECRET: z
      .string()
      .min(32)
      .default("development-kyc-signing-key-change-me"),
    KYC_RESULT_SIGNING_KEY_ID: z.string().min(1).default("development-v1"),
    /**
     * AES-256-GCM keys for stored BVNs, as {"<key id>":"<base64 32 bytes>"}.
     * Keep retired keys listed so older rows still decrypt.
     */
    KYC_IDENTITY_NUMBER_KEYS_JSON: z
      .string()
      .min(2)
      .default(
        `{"${DEVELOPMENT_IDENTITY_NUMBER_KEY_ID}":"${DEVELOPMENT_IDENTITY_NUMBER_KEY}"}`,
      ),
    KYC_IDENTITY_NUMBER_KEY_ID: z
      .string()
      .min(1)
      .default(DEVELOPMENT_IDENTITY_NUMBER_KEY_ID),
    NOTIFICATION_WORKER_ENABLED: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    RABBITMQ_URL: z.string().url().default("amqp://localhost:5672"),
    /** Relays outbox events (OTP and other notifications) to RabbitMQ. */
    OUTBOX_PUBLISHER_ENABLED: z
      .enum(["true", "false"])
      .default("false")
      .transform((value) => value === "true"),
    OUTBOX_TENANT_IDS: z
      .string()
      .default("")
      .transform((value) =>
        value
          .split(",")
          .map((tenantId) => tenantId.trim())
          .filter(Boolean),
      )
      .pipe(z.array(z.string().uuid())),
    OUTBOX_POLL_MS: z.coerce.number().int().min(100).default(1_000),
    NOTIFICATION_MAX_ATTEMPTS: z.coerce
      .number()
      .int()
      .min(1)
      .max(10)
      .default(5),
    NOTIFICATION_RETRY_BASE_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(1_000),
    NOTIFICATION_TARGET_HASH_SECRET: z
      .string()
      .min(32)
      .default("development-target-hash-secret-change-me"),
    NOTIFICATION_TARGET_HASH_KEY_ID: z
      .string()
      .min(1)
      .default("development-v1"),
    NOTIFICATION_PROVIDER_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .positive()
      .default(10_000),
    BREVO_BASE_URL: baseUrl("https://api.brevo.com"),
    BREVO_API_KEY: z.string().min(1).default("development-brevo-key-change-me"),
    BREVO_SENDER_EMAIL: z.string().email().default("no-reply@parc.invalid"),
    BREVO_SENDER_NAME: z.string().min(1).default("Parc"),
    BREVO_CONFIGURATION_VERSION: z.string().min(1).default("development-v1"),
    TERMII_BASE_URL: baseUrl("https://api.ng.termii.com"),
    TERMII_API_KEY: z
      .string()
      .min(1)
      .default("development-termii-key-change-me"),
    TERMII_SENDER_ID: z.string().min(1).max(11).default("Parc"),
    TERMII_CHANNEL: z.string().min(1).default("generic"),
    TERMII_CONFIGURATION_VERSION: z.string().min(1).default("development-v1"),
    FIREBASE_PROJECT_ID: z.string().min(1).default("development-project"),
    FCM_CONFIGURATION_VERSION: z.string().min(1).default("development-v1"),
  })
  .refine(
    ({ DATABASE_POOL_MIN, DATABASE_POOL_MAX }) =>
      DATABASE_POOL_MIN <= DATABASE_POOL_MAX,
    {
      message: "DATABASE_POOL_MIN must not exceed DATABASE_POOL_MAX",
    },
  )
  .refine(
    ({ NODE_ENV, SERVICE_CLIENT_KEYS_JSON }) =>
      NODE_ENV !== "production" || SERVICE_CLIENT_KEYS_JSON.trim() !== "{}",
    { message: "Production requires SERVICE_CLIENT_KEYS_JSON" },
  )
  .refine(
    ({ NODE_ENV, IDEMPOTENCY_HASH_SECRET }) =>
      NODE_ENV !== "production" ||
      IDEMPOTENCY_HASH_SECRET !== "development-idempotency-secret-change-me",
    { message: "Production requires IDEMPOTENCY_HASH_SECRET" },
  )
  .refine(
    ({ NODE_ENV, CHALLENGE_HASH_SECRET }) =>
      NODE_ENV !== "production" ||
      CHALLENGE_HASH_SECRET !== "development-challenge-secret-change-me",
    { message: "Production requires CHALLENGE_HASH_SECRET" },
  )
  .refine(
    ({ NODE_ENV, RATE_LIMIT_STORE }) =>
      NODE_ENV !== "production" || RATE_LIMIT_STORE === "redis",
    { message: "Production requires Redis rate limiting" },
  )
  .refine(
    ({ NODE_ENV, JWT_PRIVATE_KEY_BASE64, JWT_PUBLIC_KEYS_JSON }) =>
      NODE_ENV !== "production" ||
      Boolean(JWT_PRIVATE_KEY_BASE64 && JWT_PUBLIC_KEYS_JSON),
    { message: "Production requires asymmetric JWT key material" },
  )
  .refine(
    ({ NODE_ENV, TOKEN_HASH_SECRET }) =>
      NODE_ENV !== "production" ||
      TOKEN_HASH_SECRET !== "development-token-hash-secret-change-me",
    { message: "Production requires TOKEN_HASH_SECRET" },
  )
  .refine(
    ({
      NODE_ENV,
      KYC_IDENTITY_PROVIDER,
      KYC_FACE_PROVIDER,
      VERIFYME_API_KEY,
    }) =>
      NODE_ENV !== "production" ||
      (KYC_IDENTITY_PROVIDER !== "VERIFYME" &&
        KYC_FACE_PROVIDER !== "VERIFYME") ||
      VERIFYME_API_KEY !== "development-verifyme-key-change-me",
    { message: "Production requires VERIFYME_API_KEY" },
  )
  .refine(
    ({ NODE_ENV, KYC_IDENTITY_PROVIDER, KYC_FACE_PROVIDER, PREMBLY_API_KEY }) =>
      NODE_ENV !== "production" ||
      (KYC_IDENTITY_PROVIDER !== "PREMBLY" &&
        KYC_FACE_PROVIDER !== "PREMBLY") ||
      PREMBLY_API_KEY !== "development-prembly-key-change-me",
    { message: "Production requires PREMBLY_API_KEY" },
  )
  .refine(
    ({ NODE_ENV, PREMBLY_ALLOW_SANDBOX }) =>
      NODE_ENV !== "production" || !PREMBLY_ALLOW_SANDBOX,
    { message: "Production must not accept Prembly sandbox responses" },
  )
  .refine(
    ({ NODE_ENV, PREMBLY_DEBUG_LOG }) =>
      NODE_ENV !== "production" || !PREMBLY_DEBUG_LOG,
    { message: "Production must not log Prembly responses" },
  )
  .refine(
    ({ OUTBOX_PUBLISHER_ENABLED, OUTBOX_TENANT_IDS }) =>
      !OUTBOX_PUBLISHER_ENABLED || OUTBOX_TENANT_IDS.length > 0,
    { message: "OUTBOX_PUBLISHER_ENABLED requires OUTBOX_TENANT_IDS" },
  )
  .refine(
    ({ NODE_ENV, OUTBOX_PUBLISHER_ENABLED }) =>
      NODE_ENV !== "production" || OUTBOX_PUBLISHER_ENABLED,
    { message: "Production requires OUTBOX_PUBLISHER_ENABLED" },
  )
  .refine(
    ({ NODE_ENV, KYC_IDENTIFIER_HASH_SECRET }) =>
      NODE_ENV !== "production" ||
      KYC_IDENTIFIER_HASH_SECRET !== "development-kyc-hash-secret-change-me",
    { message: "Production requires KYC_IDENTIFIER_HASH_SECRET" },
  )
  .refine(
    ({ NODE_ENV, KYC_RESULT_SIGNING_SECRET }) =>
      NODE_ENV !== "production" ||
      KYC_RESULT_SIGNING_SECRET !== "development-kyc-signing-key-change-me",
    { message: "Production requires KYC_RESULT_SIGNING_SECRET" },
  )
  .refine(
    ({ NODE_ENV, KYC_IDENTITY_NUMBER_KEYS_JSON }) =>
      NODE_ENV !== "production" ||
      !KYC_IDENTITY_NUMBER_KEYS_JSON.includes(DEVELOPMENT_IDENTITY_NUMBER_KEY),
    { message: "Production requires KYC_IDENTITY_NUMBER_KEYS_JSON" },
  )
  .refine(
    ({ NODE_ENV, NOTIFICATION_WORKER_ENABLED }) =>
      NODE_ENV !== "production" || NOTIFICATION_WORKER_ENABLED,
    { message: "Production requires NOTIFICATION_WORKER_ENABLED" },
  )
  .refine(
    ({ NODE_ENV, NOTIFICATION_TARGET_HASH_SECRET }) =>
      NODE_ENV !== "production" ||
      NOTIFICATION_TARGET_HASH_SECRET !==
        "development-target-hash-secret-change-me",
    { message: "Production requires NOTIFICATION_TARGET_HASH_SECRET" },
  )
  .refine(
    ({ NODE_ENV, BREVO_API_KEY }) =>
      NODE_ENV !== "production" ||
      BREVO_API_KEY !== "development-brevo-key-change-me",
    { message: "Production requires BREVO_API_KEY" },
  )
  .refine(
    ({ NODE_ENV, TERMII_API_KEY }) =>
      NODE_ENV !== "production" ||
      TERMII_API_KEY !== "development-termii-key-change-me",
    { message: "Production requires TERMII_API_KEY" },
  );

export type AppConfig = z.infer<typeof environmentSchema>;

export function loadConfig(
  environment: NodeJS.ProcessEnv = process.env,
): AppConfig {
  return environmentSchema.parse(environment);
}
