import { jest } from "@jest/globals";
import { VerifyMeProvider } from "../../src/providers/verifyme-provider.js";

function provider(fetchImplementation: typeof fetch): VerifyMeProvider {
  return new VerifyMeProvider({
    baseUrl: "https://verifyme.invalid",
    apiKey: "secret",
    configurationVersion: "v1",
    timeoutMs: 100,
    fetchImplementation,
  });
}

test("maps successful VerifyMe responses to redacted results", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    new Response(
      JSON.stringify({
        status: "success",
        data: {
          id: "provider-reference",
          bvn: "10000000001",
          firstname: "Synthetic",
          fieldMatches: { firstname: true },
        },
      }),
      { status: 200 },
    ),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "BVN",
    identityValue: "10000000001",
  });
  expect(result).toEqual({
    outcome: "VERIFIED",
    providerReference: "provider-reference",
    providerConfigurationVersion: "v1",
    resultCode: "SUCCESS",
    safeResult: {
      status: "success",
      field_matches: { firstname: true },
    },
  });
  expect(JSON.stringify(result)).not.toContain("10000000001");
  expect(JSON.stringify(result)).not.toContain("Synthetic");
});

test("keeps timeouts and provider failures pending without throwing", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockRejectedValue(
      new Error("timeout containing sensitive transport data"),
    );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: "10000000001",
  });
  expect(result).toEqual({
    outcome: "PENDING",
    providerReference: "verifyme-request:verification-id",
    providerConfigurationVersion: "v1",
    resultCode: "PROVIDER_OUTCOME_UNKNOWN",
    safeResult: { status: "pending" },
  });
});

test("maps a definitive not-found response to failed", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    new Response(JSON.stringify({ code: "NOT_FOUND_ERROR" }), {
      status: 404,
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: "10000000001",
  });
  expect(result.outcome).toBe("FAILED");
  expect(result.resultCode).toBe("NOT_FOUND_ERROR");
});

test("routes incomplete matching data to manual review instead of failing identity", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    new Response(JSON.stringify({ code: "VALIDATION_ERROR" }), {
      status: 400,
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: "10000000001",
  });
  expect(result.outcome).toBe("MANUAL_REVIEW");
  expect(result.resultCode).toBe("VALIDATION_ERROR");
});

test("requires VerifyMe liveness and face-match evidence", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    new Response(
      JSON.stringify({
        isLive: true,
        identityMatches: true,
        identityDetails: { idNumber: "10000000001", photo: "sensitive" },
      }),
      { status: 200 },
    ),
  );
  const result = await provider(fetchImplementation).verifyBiometric({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: "10000000001",
    livenessReference: "face-reference",
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    providerReference: "face-reference",
    resultCode: "LIVENESS_AND_FACE_MATCHED",
    safeResult: {
      status: "success",
      liveness_verified: true,
      face_matched: true,
    },
  });
  expect(JSON.stringify(result)).not.toContain("10000000001");
  expect(JSON.stringify(result)).not.toContain("sensitive");
});
