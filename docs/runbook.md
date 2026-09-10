# Notification worker

Set `NOTIFICATION_WORKER_ENABLED=true` only when RabbitMQ, Brevo, Termii, and Firebase credentials are configured. The worker declares `parc.auth-customer.notifications.v1`, its retry queue, and `parc.auth-customer.notifications.v1.dlq` as durable quorum queues.

Monitor inbox rows in `FAILED` and `DEAD_LETTER`, retry age, provider failure codes, and retry-queue depth. Replay a dead-letter only after recording remediation; preserve the original `event_id`. Never copy message bodies, OTPs, destinations, tokens, or provider credentials into tickets or logs.

Run notification retention per tenant through `NotificationRetentionService`. It redacts expired content and metadata and removes expired attempt metadata unless `legal_hold` is true.
