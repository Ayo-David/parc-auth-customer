import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import pino from "pino";
import request from "supertest";
import { createApp } from "../../src/app.js";
import { loadConfig } from "../../src/config/env.js";
import type { KycService } from "../../src/services/kyc-service.js";
import type { OnboardingService } from "../../src/services/onboarding-service.js";
import type { OtpService } from "../../src/services/otp-service.js";

const tenantId = randomUUID();
const customerId = randomUUID();
const userId = randomUUID();
const consentId = randomUUID();
const nin = "10000000001";
/** A JPEG header followed by enough base64 to resemble a phone selfie. */
const selfie = (bytes: number) => "/9j/4AAQ" + "A".repeat(bytes);

function verification(identityType: "NIN" | "BIOMETRIC") {
  return {
    id: randomUUID(),
    identity_type: identityType,
    masked_identity: "*******0001",
    provider: "PREMBLY",
    status: "VERIFIED",
    created_at: new Date().toISOString(),
  };
}

function setup() {
  const kyc = {
    start: jest.fn(async () => verification("NIN")),
    startBiometric: jest.fn(async () => verification("BIOMETRIC")),
  };
  const onboarding = {
    userIdForCustomer: jest.fn(async () => userId),
    markIdentity: jest.fn(async () => ({ current_step: "FACE_VERIFICATION" })),
    markFaceVerified: jest.fn(async () => ({ current_step: "ADDRESS" })),
    status: jest.fn(async () => ({ current_step: "IDENTITY" })),
    registeredName: jest.fn(async () => ({
      first_name: "Ada",
      middle_name: null,
      last_name: "Okafor",
    })),
  };
  const app = createApp({
    config: loadConfig({ NODE_ENV: "test", LOG_LEVEL: "silent" }),
    logger: pino({ level: "silent" }),
    accessTokenVerifier: {
      verify: async () => ({
        subject: customerId,
        tenantId,
        audience: "mobile-bff" as const,
      }),
    },
    kycService: kyc as unknown as KycService,
    onboardingService: onboarding as unknown as OnboardingService,
    otpService: {} as OtpService,
  });
  const post = (path: string) =>
    request(app)
      .post(path)
      .set("authorization", "Bearer token")
      .set("x-tenant-id", tenantId)
      .set("idempotency-key", randomUUID());
  return { kyc, onboarding, post };
}

test("returns the NIN-registered name once identity is verified", async () => {
  const { kyc, post } = setup();
  const response = await post("/v1/onboarding/identity").send({
    identity_type: "NIN",
    identity_value: nin,
    consent_id: consentId,
  });
  expect(response.status).toBe(202);
  expect(response.body).toMatchObject({
    verification: { status: "VERIFIED", provider: "PREMBLY" },
    onboarding: { current_step: "FACE_VERIFICATION" },
    identity: { first_name: "Ada", middle_name: null, last_name: "Okafor" },
  });
  expect(kyc.start).toHaveBeenCalledWith(
    expect.objectContaining({ userId, identityValue: nin }),
  );
});

test("accepts a phone-sized selfie and passes it as face evidence", async () => {
  const { kyc, onboarding, post } = setup();
  const image = selfie(900_000);
  const response = await post("/v1/onboarding/face-verification").send({
    identity_type: "NIN",
    identity_value: nin,
    selfie_image: `data:image/jpeg;base64,${image}`,
    consent_id: consentId,
  });
  expect(response.status).toBe(202);
  expect(response.body.onboarding).toEqual({ current_step: "ADDRESS" });
  expect(kyc.startBiometric).toHaveBeenCalledWith(
    expect.objectContaining({
      evidence: { kind: "SELFIE_IMAGE", imageBase64: image },
    }),
  );
  expect(onboarding.markFaceVerified).toHaveBeenCalled();
});

test("still accepts a provider liveness reference", async () => {
  const { kyc, post } = setup();
  const response = await post("/v1/onboarding/face-verification").send({
    identity_type: "NIN",
    identity_value: nin,
    liveness_reference: "sdk-session-1",
    consent_id: consentId,
  });
  expect(response.status).toBe(202);
  expect(kyc.startBiometric).toHaveBeenCalledWith(
    expect.objectContaining({
      evidence: { kind: "LIVENESS_REFERENCE", reference: "sdk-session-1" },
    }),
  );
});

test.each([
  ["no face evidence", {}],
  [
    "both kinds of face evidence",
    { liveness_reference: "sdk-session-1", selfie_image: selfie(2_000) },
  ],
  [
    "a selfie that is not a JPEG or PNG",
    { selfie_image: "R0lGOD" + "A".repeat(2_000) },
  ],
])("rejects %s", async (_label, evidence) => {
  const { kyc, post } = setup();
  const response = await post("/v1/onboarding/face-verification").send({
    identity_type: "NIN",
    identity_value: nin,
    consent_id: consentId,
    ...evidence,
  });
  expect(response.status).toBe(400);
  expect(response.body.code).toBe("INVALID_REQUEST");
  expect(JSON.stringify(response.body)).not.toContain(nin);
  expect(kyc.startBiometric).not.toHaveBeenCalled();
});

test("rejects a selfie over the face-verification limit", async () => {
  const { kyc, post } = setup();
  const response = await post("/v1/onboarding/face-verification").send({
    identity_type: "NIN",
    identity_value: nin,
    selfie_image: selfie(2_200_000),
    consent_id: consentId,
  });
  expect(response.status).toBe(413);
  expect(kyc.startBiometric).not.toHaveBeenCalled();
});

test("keeps the default body limit on other onboarding routes", async () => {
  const { kyc, post } = setup();
  const response = await post("/v1/onboarding/identity").send({
    identity_type: "NIN",
    identity_value: nin,
    consent_id: consentId,
    padding: "A".repeat(300_000),
  });
  expect(response.status).toBe(413);
  expect(response.body.code).toBe("PAYLOAD_TOO_LARGE");
  expect(kyc.start).not.toHaveBeenCalled();
});
