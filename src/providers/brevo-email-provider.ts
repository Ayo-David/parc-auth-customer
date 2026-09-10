import { z } from "zod";
import {
  safeProviderFailure,
  type NotificationMessage,
  type NotificationProvider,
  type NotificationProviderResult,
} from "./notification-provider.js";

const responseSchema = z
  .object({ messageId: z.string().optional() })
  .passthrough();

export class BrevoEmailProvider implements NotificationProvider {
  public readonly name = "BREVO" as const;
  public constructor(
    public readonly configurationVersion: string,
    private readonly options: {
      baseUrl: string;
      apiKey: string;
      senderEmail: string;
      senderName: string;
      timeoutMs: number;
      fetchImplementation?: typeof fetch;
    },
  ) {}

  public async send(
    message: NotificationMessage,
  ): Promise<NotificationProviderResult> {
    try {
      const response = await (this.options.fetchImplementation ?? fetch)(
        `${this.options.baseUrl}/v3/smtp/email`,
        {
          method: "POST",
          headers: {
            "api-key": this.options.apiKey,
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            sender: {
              email: this.options.senderEmail,
              name: this.options.senderName,
            },
            to: [{ email: message.destination }],
            subject: message.subject ?? "Parc notification",
            textContent: message.body,
            headers: { "Idempotency-Key": message.notificationId },
          }),
          signal: AbortSignal.timeout(this.options.timeoutMs),
        },
      );
      if (!response.ok) return safeProviderFailure(response.status);
      const parsed = responseSchema.safeParse(
        await response.json().catch(() => ({})),
      );
      return {
        status: "SENT",
        ...(parsed.success && parsed.data.messageId
          ? { providerReference: parsed.data.messageId }
          : {}),
      };
    } catch {
      return { status: "RETRYABLE", failureCode: "PROVIDER_OUTCOME_UNKNOWN" };
    }
  }
}
