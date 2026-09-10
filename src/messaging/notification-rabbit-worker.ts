import amqp, { type ChannelModel, type ConfirmChannel } from "amqplib";
import type { Logger } from "pino";
import type { NotificationWorkerService } from "../services/notification-worker-service.js";

const exchange = "parc.events";
const routingKey = "notification.requested.v1";
const queue = "parc.auth-customer.notifications.v1";
const retryQueue = `${queue}.retry`;
const deadLetterQueue = `${queue}.dlq`;

export class NotificationRabbitWorker {
  private connection?: ChannelModel;
  private channel?: ConfirmChannel;

  public constructor(
    private readonly url: string,
    private readonly service: NotificationWorkerService,
    private readonly logger: Logger,
  ) {}

  public async start(): Promise<void> {
    this.connection = await amqp.connect(this.url);
    this.channel = await this.connection.createConfirmChannel();
    await this.channel.assertExchange(exchange, "topic", { durable: true });
    await this.channel.assertQueue(deadLetterQueue, {
      durable: true,
      arguments: { "x-queue-type": "quorum" },
    });
    await this.channel.assertQueue(queue, {
      durable: true,
      arguments: {
        "x-queue-type": "quorum",
        "x-dead-letter-exchange": "",
        "x-dead-letter-routing-key": deadLetterQueue,
      },
    });
    await this.channel.assertQueue(retryQueue, {
      durable: true,
      arguments: {
        "x-queue-type": "quorum",
        "x-dead-letter-exchange": exchange,
        "x-dead-letter-routing-key": routingKey,
      },
    });
    await this.channel.bindQueue(queue, exchange, routingKey);
    await this.channel.prefetch(10);
    await this.channel.consume(queue, (message) => {
      if (!message || !this.channel) return;
      void this.consume(message.content, message).catch((error: unknown) => {
        this.logger.error(
          { err: error },
          "Notification message processing failed",
        );
        this.channel?.reject(message, false);
      });
    });
  }

  public async close(): Promise<void> {
    await this.channel?.close();
    await this.connection?.close();
  }

  private async consume(
    content: Buffer,
    message: Parameters<ConfirmChannel["ack"]>[0],
  ): Promise<void> {
    if (!this.channel) return;
    const event: unknown = JSON.parse(content.toString("utf8"));
    const result = await this.service.handle(event);
    if (result.action === "RETRY") {
      this.channel.sendToQueue(retryQueue, content, {
        persistent: true,
        contentType: "application/json",
        expiration: String(Math.max(1, result.retryDelayMs ?? 1_000)),
        messageId: message.properties.messageId,
      });
      await this.channel.waitForConfirms();
    }
    if (result.action === "DEAD_LETTER") {
      this.channel.reject(message, false);
      return;
    }
    this.channel.ack(message);
  }
}
