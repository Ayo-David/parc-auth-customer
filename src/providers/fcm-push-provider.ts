import type { Messaging } from "firebase-admin/messaging";
import type {
  NotificationMessage,
  NotificationProvider,
  NotificationProviderResult,
} from "./notification-provider.js";

export class FcmPushProvider implements NotificationProvider {
  public readonly name = "FCM" as const;
  public constructor(
    public readonly configurationVersion: string,
    private readonly messaging: Pick<Messaging, "send">,
  ) {}

  public async send(
    message: NotificationMessage,
  ): Promise<NotificationProviderResult> {
    try {
      const providerReference = await this.messaging.send({
        token: message.destination,
        notification: { title: message.subject ?? "Parc", body: message.body },
        ...(message.data ? { data: message.data } : {}),
      });
      return { status: "SENT", providerReference };
    } catch (error) {
      const code =
        typeof error === "object" && error && "code" in error
          ? String(error.code)
          : "FCM_UNKNOWN";
      const permanent = new Set([
        "messaging/invalid-registration-token",
        "messaging/registration-token-not-registered",
        "messaging/mismatched-credential",
      ]);
      return {
        status: permanent.has(code) ? "FAILED" : "RETRYABLE",
        failureCode: code.slice(0, 100),
      };
    }
  }
}
