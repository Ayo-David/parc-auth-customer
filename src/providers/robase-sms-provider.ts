import { z } from "zod";
import {
  safeProviderFailure,
  type NotificationMessage,
  type NotificationProvider,
  type NotificationProviderResult,
} from "./notification-provider.js";

const responseSchema = z
  .object({
    id: z.string().optional(),
  })
  .passthrough();

// Robase documents `error.type` as stable; `error.message` is not and may be
// translated, so only the type is kept and only in a constrained shape.
const errorSchema = z.object({
  error: z.object({ type: z.string().regex(/^[a-z][a-z0-9_]{0,63}$/) }),
});

export class RobaseSmsProvider implements NotificationProvider {
  public readonly name = "ROBASE" as const;
  public constructor(
    public readonly configurationVersion: string,
    private readonly options: {
      baseUrl: string;
      apiKey: string;
      timeoutMs: number;
      fetchImplementation?: typeof fetch;
    },
  ) {}

  public async send(
    message: NotificationMessage,
  ): Promise<NotificationProviderResult> {
    try {
      const response = await (this.options.fetchImplementation ?? fetch)(
        `${this.options.baseUrl}/v1/sms/send`,
        {
          method: "POST",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${this.options.apiKey}`,
            "content-type": "application/json",
            // Stable per notification so a worker retry after a lost response
            // replays Robase's original result instead of sending again.
            "idempotency-key": message.notificationId,
          },
          body: JSON.stringify({
            // Robase requires E.164 with the leading "+".
            phone_number: message.destination.startsWith("+")
              ? message.destination
              : `+${message.destination}`,
            message: message.body,
          }),
          signal: AbortSignal.timeout(this.options.timeoutMs),
        },
      );
      if (!response.ok) {
        const parsed = errorSchema.safeParse(
          await response.json().catch(() => ({})),
        );
        const httpCode = `HTTP_${String(response.status)}`;
        return {
          // 409 request_in_progress: an earlier attempt with this key is still running.
          status:
            response.status === 409
              ? "RETRYABLE"
              : safeProviderFailure(response.status).status,
          failureCode: parsed.success
            ? `${httpCode}:${parsed.data.error.type}`
            : httpCode,
        };
      }
      const parsed = responseSchema.safeParse(
        await response.json().catch(() => ({})),
      );
      return {
        status: "SENT",
        ...(parsed.success && parsed.data.id
          ? { providerReference: parsed.data.id }
          : {}),
      };
    } catch {
      return { status: "RETRYABLE", failureCode: "PROVIDER_OUTCOME_UNKNOWN" };
    }
  }
}
