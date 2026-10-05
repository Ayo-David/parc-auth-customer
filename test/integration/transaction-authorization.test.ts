import { randomUUID } from "node:crypto";
import { jest } from "@jest/globals";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { CustomerRepository } from "../../src/repositories/customer-repository.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { TransactionAuthorizationService } from "../../src/services/transaction-authorization-service.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});
afterAll(async () => database.destroy());

integrationTest(
  "issues, consumes once, and permits only an identical consume replay",
  async () => {
    const tenantId = randomUUID();
    const customer = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) => {
        const user = await new UserRepository(transaction).create({
          tenantId,
          phone: "+2348011111111",
          phoneNormalized: "+2348011111111",
          status: "ACTIVE",
        });
        // Authorizations key on the customer-profile ID (the access-token subject).
        return new CustomerRepository(transaction).create({
          tenantId,
          userId: user.id,
          customerNumber: `CUS-${randomUUID()}`,
        });
      },
    );
    const verify = jest.fn(async () => undefined);
    const service = new TransactionAuthorizationService(
      database,
      { verify },
      "t".repeat(32),
    );
    const issueKey = randomUUID();
    const resourceId = randomUUID();
    const issued = await service.issue({
      tenantId,
      customerId: customer.id,
      idempotencyKey: issueKey,
      commandType: "LOAN_OFFER_ACCEPT",
      resourceId,
      requestHash: "a".repeat(64),
      method: "transaction_pin",
      pin: "1234",
    });
    const replayedIssue = await service.issue({
      tenantId,
      customerId: customer.id,
      idempotencyKey: issueKey,
      commandType: "LOAN_OFFER_ACCEPT",
      resourceId,
      requestHash: "a".repeat(64),
      method: "transaction_pin",
      pin: "1234",
    });
    expect(replayedIssue).toEqual(issued);
    expect(verify).toHaveBeenCalledTimes(2);

    const consumptionKey = randomUUID();
    const consume = {
      tenantId,
      customerId: customer.id,
      commandType: "LOAN_OFFER_ACCEPT",
      resourceId,
      token: issued.authorization_token,
      serviceName: "parc-lending",
      idempotencyKey: consumptionKey,
    };
    await expect(service.consume(consume)).resolves.toMatchObject({
      customer_id: customer.id,
      replayed: false,
    });
    await expect(service.consume(consume)).resolves.toMatchObject({
      customer_id: customer.id,
      replayed: true,
    });
    await expect(
      service.consume({ ...consume, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({
      status: 409,
      code: "AUTHORIZATION_ALREADY_CONSUMED",
    });
  },
);

integrationTest(
  "rejects a token presented for a different resource",
  async () => {
    const tenantId = randomUUID();
    const customer = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) => {
        const user = await new UserRepository(transaction).create({
          tenantId,
          phone: "+2348022222223",
          phoneNormalized: "+2348022222223",
          status: "ACTIVE",
        });
        // Authorizations key on the customer-profile ID (the access-token subject).
        return new CustomerRepository(transaction).create({
          tenantId,
          userId: user.id,
          customerNumber: `CUS-${randomUUID()}`,
        });
      },
    );
    const service = new TransactionAuthorizationService(
      database,
      { verify: async () => undefined },
      "t".repeat(32),
    );
    const issued = await service.issue({
      tenantId,
      customerId: customer.id,
      idempotencyKey: randomUUID(),
      commandType: "LOAN_OFFER_ACCEPT",
      resourceId: randomUUID(),
      requestHash: "b".repeat(64),
      method: "transaction_pin",
      pin: "1234",
    });
    await expect(
      service.consume({
        tenantId,
        customerId: customer.id,
        commandType: "LOAN_OFFER_ACCEPT",
        resourceId: randomUUID(),
        token: issued.authorization_token,
        serviceName: "parc-lending",
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ status: 401, code: "AUTHORIZATION_INVALID" });
  },
);

integrationTest(
  "returns the existing authorization when concurrent issues race on the idempotency key",
  async () => {
    const tenantId = randomUUID();
    const customer = await withTenantTransaction(
      database,
      tenantId,
      async (transaction) => {
        const user = await new UserRepository(transaction).create({
          tenantId,
          phone: "+2348033333334",
          phoneNormalized: "+2348033333334",
          status: "ACTIVE",
        });
        return new CustomerRepository(transaction).create({
          tenantId,
          userId: user.id,
          customerNumber: `CUS-${randomUUID()}`,
        });
      },
    );
    const service = new TransactionAuthorizationService(
      database,
      { verify: async () => undefined },
      "t".repeat(32),
    );
    const request = {
      tenantId,
      customerId: customer.id,
      idempotencyKey: randomUUID(),
      commandType: "LOAN_OFFER_ACCEPT",
      resourceId: randomUUID(),
      requestHash: "c".repeat(64),
      method: "transaction_pin" as const,
      pin: "1234",
    };
    const [first, second] = await Promise.all([
      service.issue(request),
      service.issue(request),
    ]);
    expect(second.authorization_token).toBe(first.authorization_token);
    await expect(
      service.consume({
        tenantId,
        customerId: customer.id,
        commandType: request.commandType,
        resourceId: request.resourceId,
        token: first.authorization_token,
        serviceName: "parc-lending",
        idempotencyKey: randomUUID(),
      }),
    ).resolves.toMatchObject({ customer_id: customer.id, replayed: false });
  },
);
