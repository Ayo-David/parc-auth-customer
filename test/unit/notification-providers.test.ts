import { jest } from "@jest/globals";
import type { Messaging } from "firebase-admin/messaging";
import { BrevoEmailProvider } from "../../src/providers/brevo-email-provider.js";
import { FcmPushProvider } from "../../src/providers/fcm-push-provider.js";
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
