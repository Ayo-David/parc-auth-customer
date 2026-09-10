export type NotificationChannel = "EMAIL" | "SMS" | "PUSH";

export interface NotificationMessage {
  notificationId: string;
  destination: string;
  subject?: string;
  body: string;
  data?: Record<string, string>;
}

export interface NotificationProviderResult {
  status: "SENT" | "RETRYABLE" | "FAILED";
  providerReference?: string;
  failureCode?: string;
  safeMetadata?: Record<string, unknown>;
}

export interface NotificationProvider {
  readonly name: "BREVO" | "TERMII" | "FCM";
  readonly configurationVersion: string;
  send(message: NotificationMessage): Promise<NotificationProviderResult>;
}

export interface NotificationProviderRegistry {
  resolve(channel: NotificationChannel): NotificationProvider;
}

export class StaticNotificationProviderRegistry implements NotificationProviderRegistry {
  public constructor(
    private readonly providers: Readonly<
      Record<NotificationChannel, NotificationProvider>
    >,
  ) {}

  public resolve(channel: NotificationChannel): NotificationProvider {
    return this.providers[channel];
  }
}

export function safeProviderFailure(
  status: number,
): NotificationProviderResult {
  if (status === 408 || status === 429 || status >= 500)
    return { status: "RETRYABLE", failureCode: `HTTP_${String(status)}` };
  return { status: "FAILED", failureCode: `HTTP_${String(status)}` };
}
