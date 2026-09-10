import { z } from "zod";
import {
  safeProviderFailure,
  type NotificationMessage,
  type NotificationProvider,
  type NotificationProviderResult,
} from "./notification-provider.js";

const responseSchema = z
  .object({
    message_id: z.string().optional(),
    message: z.string().optional(),
  })
  .passthrough();

export class TermiiSmsProvider implements NotificationProvider {
  public readonly name = "TERMII" as const;
  public constructor(
    public readonly configurationVersion: string,
    private readonly options: {
      baseUrl: string;
      apiKey: string;
      senderId: string;
      channel: string;
      timeoutMs: number;
      fetchImplementation?: typeof fetch;
    },
  ) {}

  public async send(
    message: NotificationMessage,
  ): Promise<NotificationProviderResult> {
    try {
      const response = await (this.options.fetchImplementation ?? fetch)(
        `${this.options.baseUrl}/api/sms/send`,
        {
          method: "POST",
          headers: {
            accept: "application/json",
            "content-type": "application/json",
          },
          body: JSON.stringify({
            api_key: this.options.apiKey,
            to: message.destination,
            from: this.options.senderId,
            sms: message.body,
            type: "plain",
            channel: this.options.channel,
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
        ...(parsed.success && parsed.data.message_id
          ? { providerReference: parsed.data.message_id }
          : {}),
      };
    } catch {
      return { status: "RETRYABLE", failureCode: "PROVIDER_OUTCOME_UNKNOWN" };
    }
  }
}
