import { createServer } from "node:http";
import { createApp } from "./app.js";
import { loadConfig } from "./config/env.js";
import {
  checkDatabase,
  closeDatabase,
  createDatabase,
} from "./database/client.js";
import { createLogger } from "./utils/logger.js";
import { CustomerService } from "./services/customer-service.js";
import { HttpTenantAdminClient } from "./services/tenant-admin-client.js";
import { createClient } from "redis";
import {
  MemoryRateLimiter,
  RedisRateLimiter,
} from "./security/rate-limiter.js";
import { AuthenticationService } from "./services/authentication-service.js";
import {
  MemoryOtpSecretStore,
  RedisOtpSecretStore,
} from "./security/otp-secret-store.js";
import { OtpService } from "./services/otp-service.js";
import { createJwtKeyRing, publicJwks } from "./security/jwt-key-ring.js";
import { SessionService } from "./services/session-service.js";
import { AdministratorAuthenticationService } from "./services/administrator-authentication-service.js";
import { CustomerMfaService } from "./services/customer-mfa-service.js";
import { PasskeyService } from "./services/passkey-service.js";
import { VerifyMeProvider } from "./providers/verifyme-provider.js";
import { StaticKycProviderResolver } from "./providers/kyc-provider.js";
import { KycService } from "./services/kyc-service.js";
import { applicationDefault, getApps, initializeApp } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";
import { BrevoEmailProvider } from "./providers/brevo-email-provider.js";
import { TermiiSmsProvider } from "./providers/termii-sms-provider.js";
import { FcmPushProvider } from "./providers/fcm-push-provider.js";
import { StaticNotificationProviderRegistry } from "./providers/notification-provider.js";
import { NotificationWorkerService } from "./services/notification-worker-service.js";
import { NotificationRabbitWorker } from "./messaging/notification-rabbit-worker.js";
import { TransactionAuthorizationService } from "./services/transaction-authorization-service.js";
import { ApiError } from "./http/api-error.js";
import { CustomerExperienceService } from "./services/customer-experience-service.js";

const config = loadConfig();
const logger = createLogger(config);
const database = createDatabase(config);
const tenantAdmin = new HttpTenantAdminClient(
  config.TENANT_ADMIN_INTERNAL_URL,
  config.INTERNAL_SERVICE_TOKEN,
);
const redis =
  config.RATE_LIMIT_STORE === "redis"
    ? createClient({ url: config.REDIS_URL })
    : undefined;
if (redis) {
  redis.on("error", (error) => {
    logger.error({ err: error }, "Redis error");
  });
  await redis.connect();
}
const rateLimiter = redis
  ? new RedisRateLimiter(redis)
  : new MemoryRateLimiter();
const otpSecrets = redis
  ? new RedisOtpSecretStore(redis, config.CHALLENGE_HASH_SECRET)
  : new MemoryOtpSecretStore();
const jwtKeys = await createJwtKeyRing({
  activeKid: config.JWT_ACTIVE_KID,
  ...(config.JWT_PRIVATE_KEY_BASE64
    ? { privateKeyBase64: config.JWT_PRIVATE_KEY_BASE64 }
    : {}),
  ...(config.JWT_PUBLIC_KEYS_JSON
    ? { publicKeysJson: config.JWT_PUBLIC_KEYS_JSON }
    : {}),
});
const sessionService = new SessionService(
  database,
  jwtKeys,
  config.JWT_ISSUER,
  config.TOKEN_HASH_SECRET,
  tenantAdmin,
);
const authResultIssuer = sessionService;
const customerMfaService = new CustomerMfaService(
  database,
  tenantAdmin,
  otpSecrets,
  rateLimiter,
  authResultIssuer,
  config.CHALLENGE_HASH_SECRET,
);
const passkeyService = new PasskeyService(
  database,
  tenantAdmin,
  otpSecrets,
  authResultIssuer,
  sessionService,
  config.CHALLENGE_HASH_SECRET,
);
const kycProvider = new VerifyMeProvider({
  baseUrl: config.VERIFYME_BASE_URL,
  apiKey: config.VERIFYME_API_KEY,
  configurationVersion: config.VERIFYME_CONFIGURATION_VERSION,
  timeoutMs: config.VERIFYME_TIMEOUT_MS,
});
const kycService = new KycService(
  database,
  new StaticKycProviderResolver(kycProvider),
  config.IDEMPOTENCY_HASH_SECRET,
  {
    identifierHashSecret: config.KYC_IDENTIFIER_HASH_SECRET,
    identifierHashKeyId: config.KYC_IDENTIFIER_HASH_KEY_ID,
    resultSigningSecret: config.KYC_RESULT_SIGNING_SECRET,
    resultSigningKeyId: config.KYC_RESULT_SIGNING_KEY_ID,
  },
);
const notificationWorker = config.NOTIFICATION_WORKER_ENABLED
  ? new NotificationRabbitWorker(
      config.RABBITMQ_URL,
      new NotificationWorkerService(
        database,
        new StaticNotificationProviderRegistry({
          EMAIL: new BrevoEmailProvider(config.BREVO_CONFIGURATION_VERSION, {
            baseUrl: config.BREVO_BASE_URL,
            apiKey: config.BREVO_API_KEY,
            senderEmail: config.BREVO_SENDER_EMAIL,
            senderName: config.BREVO_SENDER_NAME,
            timeoutMs: config.NOTIFICATION_PROVIDER_TIMEOUT_MS,
          }),
          SMS: new TermiiSmsProvider(config.TERMII_CONFIGURATION_VERSION, {
            baseUrl: config.TERMII_BASE_URL,
            apiKey: config.TERMII_API_KEY,
            senderId: config.TERMII_SENDER_ID,
            channel: config.TERMII_CHANNEL,
            timeoutMs: config.NOTIFICATION_PROVIDER_TIMEOUT_MS,
          }),
          PUSH: new FcmPushProvider(
            config.FCM_CONFIGURATION_VERSION,
            getMessaging(
              getApps()[0] ??
                initializeApp({
                  credential: applicationDefault(),
                  projectId: config.FIREBASE_PROJECT_ID,
                }),
            ),
          ),
        }),
        otpSecrets,
        config.NOTIFICATION_TARGET_HASH_SECRET,
        config.NOTIFICATION_TARGET_HASH_KEY_ID,
        config.NOTIFICATION_MAX_ATTEMPTS,
        config.NOTIFICATION_RETRY_BASE_MS,
      ),
      logger,
    )
  : undefined;
await notificationWorker?.start();
const authenticationService = new AuthenticationService(
  database,
  rateLimiter,
  authResultIssuer,
  config.CHALLENGE_HASH_SECRET,
  customerMfaService,
);
const transactionAuthorizationService = new TransactionAuthorizationService(
  database,
  {
    async verify(input) {
      if (input.method === "transaction_pin" && input.pin) {
        await authenticationService.verifyPin(
          input.tenantId,
          input.customerId,
          input.idempotencyKey,
          input.pin,
        );
        return;
      }
      throw new ApiError(
        501,
        "BIOMETRIC_TRANSACTION_AUTHORIZATION_UNAVAILABLE",
        "Biometric transaction authorization is not configured",
      );
    },
  },
  config.TOKEN_HASH_SECRET,
);
const app = createApp({
  config,
  logger,
  readinessChecks: [
    { name: "database", check: () => checkDatabase(database) },
    ...(redis
      ? [
          {
            name: "redis",
            check: async () => {
              await redis.ping();
            },
          },
        ]
      : []),
  ],
  customerService: new CustomerService(
    database,
    tenantAdmin,
    config.IDEMPOTENCY_HASH_SECRET,
  ),
  accessTokenVerifier: sessionService,
  authenticationService,
  otpService: new OtpService(
    database,
    rateLimiter,
    otpSecrets,
    authResultIssuer,
    config.CHALLENGE_HASH_SECRET,
  ),
  sessionService,
  customerMfaService,
  passkeyService,
  kycService,
  transactionAuthorizationService,
  customerExperienceService: new CustomerExperienceService(database),
  jwks: await publicJwks(jwtKeys),
  administratorAuthenticationService: new AdministratorAuthenticationService(
    database,
    tenantAdmin,
    sessionService,
    otpSecrets,
    rateLimiter,
    config.CHALLENGE_HASH_SECRET,
    passkeyService,
  ),
});
const server = createServer(app);

server.listen(config.PORT, config.HOST, () => {
  logger.info(
    { host: config.HOST, port: config.PORT },
    "Auth & Customer service listening",
  );
});

let shuttingDown = false;
function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, "Graceful shutdown started");
  const timer = setTimeout(() => {
    logger.error("Graceful shutdown timed out");
    process.exitCode = 1;
    server.closeAllConnections();
  }, config.SHUTDOWN_TIMEOUT_MS);
  timer.unref();
  server.close((error) => {
    clearTimeout(timer);
    if (error) {
      logger.error({ err: error }, "Server close failed");
      process.exitCode = 1;
    }
    void closeDatabase(database).catch((databaseError: unknown) => {
      logger.error({ err: databaseError }, "Database close failed");
      process.exitCode = 1;
    });
    if (redis?.isOpen)
      void redis.quit().catch((redisError: unknown) => {
        logger.error({ err: redisError }, "Redis close failed");
        process.exitCode = 1;
      });
    void notificationWorker?.close().catch((workerError: unknown) => {
      logger.error({ err: workerError }, "Notification worker close failed");
      process.exitCode = 1;
    });
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
