import type { Knex } from "knex";

export interface CustomerProfileRecord {
  id: string;
  tenant_id: string;
  user_id: string;
  customer_number: string;
  first_name: string | null;
  last_name: string | null;
  created_at: Date;
  updated_at: Date;
}

export class CustomerRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async create(input: {
    tenantId: string;
    userId: string;
    customerNumber: string;
  }): Promise<CustomerProfileRecord> {
    const [record] = await this.transaction<CustomerProfileRecord>(
      "customer_profiles",
    )
      .insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        customer_number: input.customerNumber,
        first_name: null,
        last_name: null,
      })
      .returning("*");
    if (!record) throw new Error("Customer profile insert returned no record");
    return record;
  }

  public findByUserId(
    userId: string,
  ): Promise<CustomerProfileRecord | undefined> {
    return this.transaction<CustomerProfileRecord>("customer_profiles")
      .where({ user_id: userId })
      .whereNull("deleted_at")
      .first();
  }

  public findById(id: string): Promise<CustomerProfileRecord | undefined> {
    return this.transaction<CustomerProfileRecord>("customer_profiles")
      .where({ id })
      .whereNull("deleted_at")
      .first();
  }

  public async update(
    userId: string,
    input: { firstName?: string; lastName?: string },
  ): Promise<CustomerProfileRecord> {
    const changes: Record<string, unknown> = {
      updated_at: this.transaction.fn.now(),
    };
    if (input.firstName !== undefined) changes.first_name = input.firstName;
    if (input.lastName !== undefined) changes.last_name = input.lastName;
    const [record] = await this.transaction<CustomerProfileRecord>(
      "customer_profiles",
    )
      .where({ user_id: userId })
      .whereNull("deleted_at")
      .update(changes)
      .returning("*");
    if (!record) throw new Error("Customer profile not found");
    return record;
  }
}
