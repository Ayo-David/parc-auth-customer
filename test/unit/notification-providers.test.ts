import { jest } from "@jest/globals";
import type { Messaging } from "firebase-admin/messaging";
import { BrevoEmailProvider } from "../../src/providers/brevo-email-provider.js";
import { FcmPushProvider } from "../../src/providers/fcm-push-provider.js";
import { RobaseSmsProvider } from "../../src/providers/robase-sms-provider.js";
import { TermiiSmsProvider } from "../../src/providers/termii-sms-provider.js";

test("Brevo sends transactional email without leaking its API key into results", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(
      new Response(JSON.stringify({ messageId: "brevo-1" }), { status: 201 }),
    );
  const provider = new BrevoEmailProvider("v1", {
    baseUrl: "https://brevo.invalid",
    apiKey: "brevo-secret",
    senderEmail: "sender@example.com",
    senderName: "Parc",
    timeoutMs: 100,
    fetchImplementation,
  });
  const result = await provider.send({
    notificationId: "notification-1",
    destination: "person@example.com",
    subject: "Subject",
    body: "Body",
  });
  expect(result).toEqual({ status: "SENT", providerReference: "brevo-1" });
  expect(JSON.stringify(result)).not.toContain("brevo-secret");
});

test("Termii classifies throttling as retryable", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(new Response("{}", { status: 429 }));
  const provider = new TermiiSmsProvider("v1", {
    baseUrl: "https://termii.invalid",
    apiKey: "termii-secret",
    senderId: "Parc",
    channel: "generic",
    timeoutMs: 100,
    fetchImplementation,
  });
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "+2348012345678",
      body: "Body",
    }),
  ).resolves.toEqual({ status: "RETRYABLE", failureCode: "HTTP_429" });
});

test("Termii sends OTP SMS to the international number without a plus sign", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(
      new Response(JSON.stringify({ message_id: "termii-1" }), { status: 200 }),
    );
  const provider = new TermiiSmsProvider("v1", {
    baseUrl: "https://termii.invalid",
    apiKey: "termii-secret",
    senderId: "Parc",
    channel: "dnd",
    timeoutMs: 100,
    fetchImplementation,
  });
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "+2348012345678",
      body: "Your code is 123456",
    }),
  ).resolves.toEqual({ status: "SENT", providerReference: "termii-1" });
  const [url, init] = fetchImplementation.mock.calls[0] ?? [];
  expect(url).toBe("https://termii.invalid/api/sms/send");
  expect(JSON.parse(init?.body as string)).toMatchObject({
    to: "2348012345678",
    from: "Parc",
    channel: "dnd",
    type: "plain",
  });
});

function robase(response: Response) {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockResolvedValue(response);
  const provider = new RobaseSmsProvider("v1", {
    baseUrl: "https://robase.invalid",
    apiKey: "robe_secret",
    timeoutMs: 100,
    fetchImplementation,
  });
  return { provider, fetchImplementation };
}

test("Robase sends E.164 SMS with bearer auth and the notification as idempotency key", async () => {
  const { provider, fetchImplementation } = robase(
    new Response(
      JSON.stringify({
        id: "6f1c0e1e-2b55-4b8c-9d61-0c7f6a0d2b11",
        status: "pending",
      }),
      { status: 200 },
    ),
  );
  const result = await provider.send({
    notificationId: "notification-1",
    destination: "+2348012345678",
    body: "Your code is 123456",
  });
  expect(result).toEqual({
    status: "SENT",
    providerReference: "6f1c0e1e-2b55-4b8c-9d61-0c7f6a0d2b11",
  });
  expect(JSON.stringify(result)).not.toContain("robe_secret");
  const [url, init] = fetchImplementation.mock.calls[0] ?? [];
  expect(url).toBe("https://robase.invalid/v1/sms/send");
  expect(init?.headers).toMatchObject({
    authorization: "Bearer robe_secret",
    "idempotency-key": "notification-1",
  });
  expect(JSON.parse(init?.body as string)).toEqual({
    phone_number: "+2348012345678",
    message: "Your code is 123456",
  });
});

test("Robase adds the plus sign when the destination lacks one", async () => {
  const { provider, fetchImplementation } = robase(
    new Response("{}", { status: 200 }),
  );
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "2348012345678",
      body: "Body",
    }),
  ).resolves.toEqual({ status: "SENT" });
  const [, init] = fetchImplementation.mock.calls[0] ?? [];
  expect(JSON.parse(init?.body as string)).toMatchObject({
    phone_number: "+2348012345678",
  });
});

test.each([
  [429, "rate_limited", "RETRYABLE"],
  [409, "request_in_progress", "RETRYABLE"],
  [503, "screening_unavailable", "RETRYABLE"],
  [402, "insufficient_credits", "FAILED"],
  [422, "sender_id_required", "FAILED"],
  [401, "unauthorized", "FAILED"],
] as const)(
  "Robase classifies HTTP %i %s as %s and keeps only the stable error type",
  async (status, type, expected) => {
    const { provider } = robase(
      new Response(
        JSON.stringify({
          error: { type, message: "+2348012345678 robe_secret" },
        }),
        { status },
      ),
    );
    const result = await provider.send({
      notificationId: "notification-1",
      destination: "+2348012345678",
      body: "Body",
    });
    expect(result).toEqual({
      status: expected,
      failureCode: `HTTP_${String(status)}:${type}`,
    });
    expect(JSON.stringify(result)).not.toMatch(/2348012345678|robe_secret/);
  },
);

test("Robase drops an unexpected error type rather than persisting it", async () => {
  const { provider } = robase(
    new Response(JSON.stringify({ error: { type: "Bad Type! +234801" } }), {
      status: 400,
    }),
  );
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "+2348012345678",
      body: "Body",
    }),
  ).resolves.toEqual({ status: "FAILED", failureCode: "HTTP_400" });
});

test("Robase treats a network failure as an unknown, retryable outcome", async () => {
  const fetchImplementation = jest
    .fn<typeof fetch>()
    .mockRejectedValue(new Error("socket hang up"));
  const provider = new RobaseSmsProvider("v1", {
    baseUrl: "https://robase.invalid",
    apiKey: "robe_secret",
    timeoutMs: 100,
    fetchImplementation,
  });
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "+2348012345678",
      body: "Body",
    }),
  ).resolves.toEqual({
    status: "RETRYABLE",
    failureCode: "PROVIDER_OUTCOME_UNKNOWN",
  });
});

test("FCM treats an unregistered token as a permanent target failure", async () => {
  const messaging: Pick<Messaging, "send"> = {
    send: jest.fn(async () => {
      throw Object.assign(new Error("unregistered"), {
        code: "messaging/registration-token-not-registered",
      });
    }),
  };
  const provider = new FcmPushProvider("v1", messaging);
  await expect(
    provider.send({
      notificationId: "notification-1",
      destination: "device-token",
      body: "Body",
    }),
  ).resolves.toEqual({
    status: "FAILED",
    failureCode: "messaging/registration-token-not-registered",
  });
});
