import type { Knex } from "knex";
import type { CredentialRecord, CredentialType } from "./types.js";

export class CredentialRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async create(input: {
    tenantId: string;
    userId: string;
    type: CredentialType;
    hash: string;
    expiresAt?: Date;
  }): Promise<CredentialRecord> {
    const [record] = await this.transaction<CredentialRecord>(
      "user_credentials",
    )
      .insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        credential_type: input.type,
        credential_hash: input.hash,
        expires_at: input.expiresAt ?? null,
      })
      .returning("*");
    if (!record) throw new Error("Credential insert returned no record");
    return record;
  }

  public findActive(
    userId: string,
    type: CredentialType,
  ): Promise<CredentialRecord | undefined> {
    return this.transaction<CredentialRecord>("user_credentials")
      .where({ user_id: userId, credential_type: type, is_active: true })
      .whereNull("deleted_at")
      .first();
  }

  public async touchLastUsed(id: string): Promise<void> {
    await this.transaction("user_credentials")
      .where({ id })
      .update({ last_used_at: this.transaction.fn.now() });
  }

  public async replace(input: {
    tenantId: string;
    userId: string;
    type: CredentialType;
    hash: string;
    reason: string;
  }): Promise<CredentialRecord> {
    const current = await this.transaction<CredentialRecord>("user_credentials")
      .where({ user_id: input.userId, credential_type: input.type })
      .whereNull("deleted_at")
      .forUpdate()
      .first();
    const version = (current?.credential_version ?? 0) + 1;
    if (current) {
      await this.transaction("credential_history").insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        credential_type: input.type,
        credential_hash: current.credential_hash,
        credential_version: current.credential_version,
        change_reason: input.reason,
        replaced_credential_id: current.id,
      });
      await this.transaction("user_credentials")
        .where({ id: current.id })
        .update({ is_active: false, deleted_at: this.transaction.fn.now() });
    }
    const [record] = await this.transaction<CredentialRecord>(
      "user_credentials",
    )
      .insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        credential_type: input.type,
        credential_hash: input.hash,
        credential_version: version,
      })
      .returning("*");
    if (!record) throw new Error("Credential replacement returned no record");
    return record;
  }

  public async recentHashes(
    userId: string,
    type: CredentialType,
    limit = 5,
  ): Promise<string[]> {
    const current = await this.findActive(userId, type);
    const history = (await this.transaction("credential_history")
      .where({ user_id: userId, credential_type: type })
      .orderBy("created_at", "desc")
      .limit(limit)) as { credential_hash: string }[];
    return [
      ...(current ? [current.credential_hash] : []),
      ...history.map(({ credential_hash }) => credential_hash),
    ].slice(0, limit);
  }
}
