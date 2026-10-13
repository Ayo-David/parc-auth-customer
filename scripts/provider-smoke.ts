/**
 * Calls the real KYC and SMS providers with the configured keys and prints only
 * the outcome, so credentials and paths can be checked before mobile testing.
 *
 *   node --env-file=.env --import tsx scripts/provider-smoke.ts prembly-nin <nin>
 *   node --env-file=.env --import tsx scripts/provider-smoke.ts prembly-face <nin> <selfie.jpg>
 *   node --env-file=.env --import tsx scripts/provider-smoke.ts termii <+234...>
 *   node --env-file=.env --import tsx scripts/provider-smoke.ts prembly-nin-shape <nin>
 *
 * The -shape command prints the raw response's field names and value types,
 * never the values, for checking where Prembly puts each field.
 */
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { z } from "zod";
import { loadConfig } from "../src/config/env.js";
import { PremblyProvider } from "../src/providers/prembly-provider.js";
import { TermiiSmsProvider } from "../src/providers/termii-sms-provider.js";

// Smoke tests only need provider settings, not a bootable production config.
const config = loadConfig({ ...process.env, NODE_ENV: "development" });
const [command, first, second] = process.argv.slice(2);
const nin = z.string().regex(/^[0-9]{11}$/, "NIN must be 11 digits");

const prembly = new PremblyProvider({
  baseUrl: config.PREMBLY_BASE_URL,
  apiKey: config.PREMBLY_API_KEY,
  ...(config.PREMBLY_APP_ID ? { appId: config.PREMBLY_APP_ID } : {}),
  configurationVersion: config.PREMBLY_CONFIGURATION_VERSION,
  timeoutMs: config.PREMBLY_TIMEOUT_MS,
  faceMatchThreshold: config.PREMBLY_FACE_MATCH_THRESHOLD,
  livenessMinimumPercent: config.PREMBLY_LIVENESS_MIN_PERCENT,
  allowSandbox: config.PREMBLY_ALLOW_SANDBOX,
});

/** Field names and value types only; no provider values are printed. */
function shape(value: unknown): unknown {
  if (Array.isArray(value)) return value.length === 0 ? [] : [shape(value[0])];
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, inner]) => [key, shape(inner)]),
    );
  if (typeof value === "string")
    return value === "" ? "string(empty)" : "string";
  return value === null ? "null" : typeof value;
}

if (command === "prembly-nin-shape") {
  const response = await fetch(
    `${config.PREMBLY_BASE_URL}/verification/vnin-basic`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-api-key": config.PREMBLY_API_KEY,
        ...(config.PREMBLY_APP_ID ? { "app-id": config.PREMBLY_APP_ID } : {}),
      },
      body: JSON.stringify({ number: nin.parse(first) }),
      signal: AbortSignal.timeout(config.PREMBLY_TIMEOUT_MS),
    },
  );
  const body = (await response.json().catch(() => ({}))) as Record<
    string,
    unknown
  >;
  console.log(
    JSON.stringify(
      {
        http_status: response.status,
        status: body.status,
        response_code: body.response_code,
        shape: shape(body),
      },
      null,
      2,
    ),
  );
} else if (command === "prembly-nin") {
  const result = await prembly.verifyIdentity({
    verificationId: randomUUID(),
    identityType: "NIN",
    identityValue: nin.parse(first),
  });
  console.log({
    outcome: result.outcome,
    resultCode: result.resultCode,
    providerReference: result.providerReference,
    nameReturned: Boolean(
      result.identityAttributes?.firstName &&
      result.identityAttributes.lastName,
    ),
    dateOfBirthReturned: Boolean(result.identityAttributes?.dateOfBirth),
  });
} else if (command === "prembly-face") {
  const result = await prembly.verifyFace({
    verificationId: randomUUID(),
    identityType: "NIN",
    identityValue: nin.parse(first),
    evidence: {
      kind: "SELFIE_IMAGE",
      imageBase64: readFileSync(z.string().min(1).parse(second)).toString(
        "base64",
      ),
    },
  });
  console.log({
    outcome: result.outcome,
    resultCode: result.resultCode,
    providerReference: result.providerReference,
    ...result.safeResult,
  });
} else if (command === "termii") {
  const destination = z
    .string()
    .regex(/^\+234[789][01][0-9]{8}$/)
    .parse(first);
  const result = await new TermiiSmsProvider(
    config.TERMII_CONFIGURATION_VERSION,
    {
      baseUrl: config.TERMII_BASE_URL,
      apiKey: config.TERMII_API_KEY,
      senderId: config.TERMII_SENDER_ID,
      channel: config.TERMII_CHANNEL,
      timeoutMs: config.NOTIFICATION_PROVIDER_TIMEOUT_MS,
    },
  ).send({
    notificationId: randomUUID(),
    destination,
    body: "Parc test message: your SMS delivery is working.",
  });
  console.log(result);
} else {
  console.error(
    "Usage: provider-smoke.ts prembly-nin <nin> | prembly-face <nin> <selfie.jpg> | termii <+234...>",
  );
  process.exitCode = 1;
}
