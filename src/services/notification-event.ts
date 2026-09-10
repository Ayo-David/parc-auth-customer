import { z } from "zod";

const channelSchema = z.enum(["EMAIL", "SMS", "PUSH"]);
const classificationSchema = z.enum([
  "NON_FINANCIAL",
  "FINANCIAL",
  "CONTRACTUAL",
  "KYC",
  "SECURITY",
  "COMPLAINT",
]);

export const notificationRequestedSchema = z
  .object({
    event_id: z.string().uuid(),
    event_type: z.literal("notification.requested.v1"),
    event_version: z.literal(1),
    occurred_at: z.string().datetime(),
    producer: z.string().min(1).max(100),
    tenant_id: z.string().uuid(),
    aggregate_type: z.literal("notification"),
    aggregate_id: z.string().uuid(),
    aggregate_version: z.number().int().positive(),
    correlation_id: z.string().uuid(),
    causation_id: z.string().uuid().nullable(),
    idempotency_key: z.string().min(1).max(255),
    data_classification: z.string(),
    payload: z
      .object({
        notification_id: z.string().uuid(),
        recipient_id: z.string().uuid(),
        channel: channelSchema,
        template_code: z.string().min(1).max(100),
        classification: classificationSchema,
        template_data: z.record(z.unknown()).default({}),
      })
      .strict(),
  })
  .strict();

export type NotificationRequested = z.infer<typeof notificationRequestedSchema>;
export type NotificationClassification = z.infer<typeof classificationSchema>;
