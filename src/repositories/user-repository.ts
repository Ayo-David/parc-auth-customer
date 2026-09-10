import type { Knex } from "knex";
import type { UserRecord, UserStatus } from "./types.js";

export interface CreateUserInput {
  tenantId: string;
  phone?: string;
  email?: string;
  phoneNormalized?: string;
  emailNormalized?: string;
  status?: UserStatus;
}

export class UserRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async create(input: CreateUserInput): Promise<UserRecord> {
    const [record] = await this.transaction("users")
      .insert({
        tenant_id: input.tenantId,
        phone: input.phone ?? null,
        email: input.email ?? null,
        phone_normalized: input.phoneNormalized ?? null,
        email_normalized: input.emailNormalized ?? null,
        status: input.status ?? "PENDING",
        user_type: "CUSTOMER",
      })
      .returning([
        "id",
        "tenant_id",
        "user_type",
        "status",
        "phone",
        "email",
        "phone_normalized",
        "email_normalized",
        "created_at",
        "updated_at",
      ]);
    if (!record) throw new Error("User insert returned no record");
    return record;
  }

  public findById(id: string): Promise<UserRecord | undefined> {
    return this.transaction<UserRecord>("users")
      .where({ id })
      .whereNull("deleted_at")
      .first();
  }

  public findByCanonicalIdentifier(
    tenantId: string,
    identifier: string,
  ): Promise<UserRecord | undefined> {
    return this.transaction<UserRecord>("users")
      .where({ tenant_id: tenantId })
      .whereNull("deleted_at")
      .andWhere((query) =>
        query
          .where("phone_normalized", identifier)
          .orWhere("email_normalized", identifier),
      )
      .first();
  }

  public async updateEmail(input: {
    id: string;
    email: string;
    emailNormalized: string;
  }): Promise<UserRecord> {
    const [record] = await this.transaction("users")
      .where({ id: input.id })
      .whereNull("deleted_at")
      .update({
        email: input.email,
        email_normalized: input.emailNormalized,
        email_verified: false,
        email_verified_at: null,
        updated_at: this.transaction.fn.now(),
      })
      .returning("*");
    if (!record) throw new Error("User not found");
    return record;
  }
}
