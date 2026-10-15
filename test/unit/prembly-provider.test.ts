import { jest } from "@jest/globals";
import { PremblyProvider } from "../../src/providers/prembly-provider.js";

const nin = "10000000001";
const selfie = "/9j/4AAQSkZJRgABAQAAAQABAAD";

function provider(
  fetchImplementation: typeof fetch,
  allowSandbox = false,
): PremblyProvider {
  return new PremblyProvider({
    baseUrl: "https://prembly.invalid",
    apiKey: "prembly-secret",
    appId: "prembly-app",
    configurationVersion: "v1",
    timeoutMs: 100,
    faceMatchThreshold: 80,
    livenessMinimumPercent: 90,
    allowSandbox,
    fetchImplementation,
  });
}

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function requestBody(
  fetchImplementation: jest.Mock<typeof fetch>,
  call: number,
): Record<string, unknown> {
  const init = fetchImplementation.mock.calls[call]?.[1];
  return JSON.parse(init?.body as string) as Record<string, unknown>;
}

test("returns the registered name from a NIN without storing it in the result", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      verification: { reference: "prembly-ref-1", status: "VERIFIED" },
      nin_data: {
        nin,
        firstname: "ADA",
        middlename: "",
        surname: "OKAFOR-NWOSU",
        birthdate: "15-05-1990",
        nin_suspension_status: false,
        photo: "sensitive-photo",
        telephoneno: "08000000000",
      },
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toEqual({
    outcome: "VERIFIED",
    providerReference: "prembly-ref-1",
    providerConfigurationVersion: "v1",
    resultCode: "SUCCESS",
    safeResult: { status: "success" },
    identityAttributes: {
      firstName: "Ada",
      lastName: "Okafor-Nwosu",
      dateOfBirth: "1990-05-15",
    },
  });
  const [url, init] = fetchImplementation.mock.calls[0] ?? [];
  expect(url).toBe("https://prembly.invalid/verification/vnin-basic");
  expect(init?.headers).toMatchObject({
    "x-api-key": "prembly-secret",
    "app-id": "prembly-app",
  });
  expect(requestBody(fetchImplementation, 0)).toEqual({ number: nin });
  const stored = { ...result, identityAttributes: undefined };
  expect(JSON.stringify(stored)).not.toMatch(/Ada|sensitive|08000000000/);
  expect(JSON.stringify(stored)).not.toContain(nin);
});

test("sends a suspended NIN to manual review", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      nin_data: {
        nin,
        firstname: "Ada",
        surname: "Okafor",
        nin_suspension_status: true,
      },
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "MANUAL_REVIEW",
    resultCode: "NIN_SUSPENDED",
  });
  expect(result.identityAttributes).toBeUndefined();
});

test("fails a NIN that Prembly cannot find", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(
      json({ status: false, response_code: "01", detail: "No record found" }),
    );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({ outcome: "FAILED", resultCode: "PREMBLY_01" });
});

test.each([
  ["an authentication error", () => json({}, 401), "HTTP_401"],
  ["a server error", () => json({}, 503), "HTTP_503"],
])(
  "keeps %s pending because the NIN was never checked",
  async (_label, response, code) => {
    const fetchImplementation = jest
      .fn<typeof fetch>()
      .mockResolvedValue(response());
    const result = await provider(fetchImplementation).verifyIdentity({
      verificationId: "verification-id",
      identityType: "NIN",
      identityValue: nin,
    });
    expect(result).toMatchObject({ outcome: "PENDING", resultCode: code });
  },
);

test("keeps transport failures pending without leaking error details", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockRejectedValue(new Error(`timeout for ${nin}`));
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "PENDING",
    resultCode: "PROVIDER_OUTCOME_UNKNOWN",
  });
  expect(JSON.stringify(result)).not.toContain(nin);
});

test("verifies a live selfie that matches the NIN photo", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        data: { confidence: 0.99, confidence_in_percentage: 99 },
      }),
    )
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        face_data: { status: true, message: "Face Match", confidence: 96 },
        verification: { reference: "prembly-face-1" },
        nin_data: { nin, photo: "sensitive-photo" },
      }),
    );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toEqual({
    outcome: "VERIFIED",
    providerReference: "prembly-face-1",
    providerConfigurationVersion: "v1",
    resultCode: "LIVENESS_AND_FACE_MATCHED",
    safeResult: {
      status: "success",
      liveness_verified: true,
      face_matched: true,
    },
  });
  expect(fetchImplementation.mock.calls.map(([url]) => url)).toEqual([
    "https://prembly.invalid/verification/biometrics/face/liveliness_check",
    "https://prembly.invalid/verification/nin_w_face",
  ]);
  expect(requestBody(fetchImplementation, 0)).toEqual({ image: selfie });
  expect(requestBody(fetchImplementation, 1)).toEqual({
    number: nin,
    image: selfie,
    face_confidence_threshold: 80,
  });
  expect(JSON.stringify(result)).not.toMatch(/sensitive|10000000001|9j/);
});

test("stops before face matching when liveness is too low", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      data: { confidence: 0.4, confidence_in_percentage: 40 },
    }),
  );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({
    outcome: "FAILED",
    resultCode: "LIVENESS_NOT_DETECTED",
    safeResult: { liveness_verified: false, face_matched: false },
  });
  expect(fetchImplementation).toHaveBeenCalledTimes(1);
});

test("fails a live selfie that does not match the NIN photo", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      json({ status: true, response_code: "00", data: { confidence: 0.98 } }),
    )
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        face_data: { status: false, message: "Face does not match" },
      }),
    );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({
    outcome: "FAILED",
    resultCode: "FACE_NOT_MATCHED",
    safeResult: { liveness_verified: true, face_matched: false },
  });
});

test("fails a face match whose live record carries no NIN", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      json({ status: true, response_code: "00", data: { confidence: 0.98 } }),
    )
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        face_data: { status: true, confidence: 96 },
        nin_data: { firstname: "Ada", surname: "Okafor" },
      }),
    );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({
    outcome: "FAILED",
    resultCode: "FACE_NOT_MATCHED",
  });
});

test("keeps the face check pending when Prembly is unavailable", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(json({}, 502));
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({ outcome: "PENDING", resultCode: "HTTP_502" });
  expect(fetchImplementation).toHaveBeenCalledTimes(1);
});

test("rejects a liveness reference without calling Prembly", async () => {
  const fetchImplementation = jest.fn<typeof fetch>();
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "LIVENESS_REFERENCE", reference: "sdk-session" },
  });
  expect(result).toMatchObject({
    outcome: "FAILED",
    resultCode: "FACE_EVIDENCE_UNSUPPORTED",
  });
  expect(fetchImplementation).not.toHaveBeenCalled();
});

// Shapes observed from the Prembly API, which nests records under `data`.
test("reads the NIN record Prembly returns under data", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      verification: { reference: "prembly-ref-2" },
      data: {
        nin,
        firstname: "ADA",
        surname: "OKAFOR",
        birthdate: "15-05-1990",
      },
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    identityAttributes: {
      firstName: "Ada",
      lastName: "Okafor",
      dateOfBirth: "1990-05-15",
    },
  });
});

test("reads the face match Prembly returns under data", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      json({ status: true, response_code: "00", data: { confidence: 0.99 } }),
    )
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        data: {
          status: true,
          nin_data: { nin, photo: "sensitive-photo" },
          face_data: { status: true, confidence: 99.9 },
        },
      }),
    );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    resultCode: "LIVENESS_AND_FACE_MATCHED",
  });
});

const sandboxRecord = {
  status: true,
  response_code: "00",
  is_sandbox: true,
  data: { nin: "99999999999", firstname: "TEST", surname: "USER" },
};

test("refuses sandbox responses unless sandbox is allowed", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(json(sandboxRecord));
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "PENDING",
    resultCode: "PROVIDER_SANDBOX_RESPONSE",
  });
  expect(result.identityAttributes).toBeUndefined();
});

test("accepts the canned sandbox record when sandbox is allowed", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(json(sandboxRecord));
  const result = await provider(fetchImplementation, true).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    identityAttributes: { firstName: "Test", lastName: "User" },
  });
});

test("still rejects a different NIN record from the live API", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(json({ ...sandboxRecord, is_sandbox: false }));
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(result).toMatchObject({
    outcome: "MANUAL_REVIEW",
    resultCode: "IDENTITY_MISMATCH",
  });
});

test("debug logging prints each call with the NIN masked and images trimmed", async () => {
  const log = jest.spyOn(console, "log").mockImplementation(() => undefined);
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      data: {
        nin,
        firstname: "ADA",
        surname: "OBI",
        photo: "A".repeat(4096),
      },
    }),
  );
  await new PremblyProvider({
    baseUrl: "https://prembly.invalid",
    apiKey: "prembly-secret",
    configurationVersion: "v1",
    timeoutMs: 100,
    faceMatchThreshold: 80,
    livenessMinimumPercent: 90,
    allowSandbox: false,
    debugLog: true,
    fetchImplementation,
  }).verifyIdentity({
    verificationId: "verification-1",
    identityType: "NIN",
    identityValue: nin,
  });
  const output = log.mock.calls.map((call) => String(call[0])).join("\n");
  log.mockRestore();

  expect(output).toContain("Prembly · NIN lookup");
  expect(output).toContain("Prembly decision: VERIFIED · SUCCESS");
  expect(output).toContain('"nin": "*******0001"');
  expect(output).toContain("[base64, 4.0 KB]");
  expect(output).not.toContain(nin);
  expect(output).not.toContain("prembly-secret");
});

test("stays silent when debug logging is off", async () => {
  const log = jest.spyOn(console, "log").mockImplementation(() => undefined);
  await provider(
    jest
      .fn<typeof fetch>()
      .mockResolvedValue(json({ status: true, response_code: "00" })),
  ).verifyIdentity({
    verificationId: "verification-1",
    identityType: "NIN",
    identityValue: nin,
  });
  expect(log).not.toHaveBeenCalled();
  log.mockRestore();
});

const bvn = "22222222222";

test("returns the registered name from a BVN, reading Prembly's camelCase record", async () => {
  const fetchImplementation = jest.fn<typeof fetch>().mockResolvedValue(
    json({
      status: true,
      response_code: "00",
      verification: { reference: "prembly-bvn-1" },
      data: {
        firstName: "AYO",
        middleName: "DAVID",
        lastName: "AJAYI",
        dateOfBirth: "01-Jan-2000",
        phoneNumber: "08000000000",
      },
    }),
  );
  const result = await provider(fetchImplementation).verifyIdentity({
    verificationId: "verification-id",
    identityType: "BVN",
    identityValue: bvn,
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    providerReference: "prembly-bvn-1",
    resultCode: "SUCCESS",
    identityAttributes: {
      firstName: "Ayo",
      middleName: "David",
      lastName: "Ajayi",
      dateOfBirth: "2000-01-01",
    },
  });
  expect(fetchImplementation.mock.calls[0]?.[0]).toBe(
    "https://prembly.invalid/verification/bvn_validation",
  );
  expect(requestBody(fetchImplementation, 0)).toEqual({ number: bvn });
});

test("sends a BVN whose returned record carries a different number to manual review", async () => {
  const result = await provider(
    jest.fn<typeof fetch>().mockResolvedValue(
      json({
        status: true,
        response_code: "00",
        data: { bvn: "33333333333", firstName: "AYO", lastName: "AJAYI" },
      }),
    ),
  ).verifyIdentity({
    verificationId: "verification-id",
    identityType: "BVN",
    identityValue: bvn,
  });
  expect(result).toMatchObject({
    outcome: "MANUAL_REVIEW",
    resultCode: "IDENTITY_MISMATCH",
  });
});

test("matches a live selfie against the BVN photo", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        data: { confidence_in_percentage: 99 },
      }),
    )
    .mockResolvedValueOnce(
      json({
        status: true,
        response_code: "00",
        verification: { reference: "prembly-bvn-face-1" },
        data: {
          bvn,
          firstName: "AYO",
          lastName: "AJAYI",
          base64Image: "A".repeat(400),
          face_data: { status: true, confidence: 95, threshold: 80 },
        },
      }),
    );
  const result = await provider(fetchImplementation).verifyFace({
    verificationId: "verification-id",
    identityType: "BVN",
    identityValue: bvn,
    evidence: { kind: "SELFIE_IMAGE", imageBase64: selfie },
  });
  expect(result).toMatchObject({
    outcome: "VERIFIED",
    resultCode: "LIVENESS_AND_FACE_MATCHED",
  });
  expect(fetchImplementation.mock.calls[1]?.[0]).toBe(
    "https://prembly.invalid/verification/bvn_w_face",
  );
  expect(requestBody(fetchImplementation, 1)).toEqual({
    number: bvn,
    image: selfie,
    face_confidence_threshold: 80,
  });
});
