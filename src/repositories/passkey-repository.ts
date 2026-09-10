import type { Knex } from "knex";

export interface PasskeyRecord {
  id: string;
  tenant_id: string | null;
  user_id: string | null;
  subject_id: string;
  subject_type: "CUSTOMER" | "ADMINISTRATOR";
  scope_type: "TENANT" | "PLATFORM";
  credential_id: string;
  public_key: string;
  relying_party_id: string;
  aaguid: string | null;
  sign_count: string;
  transports: string[];
  backup_eligible: boolean;
  backup_state: boolean;
  device_type: string | null;
  friendly_name: string | null;
  last_used_at: Date | null;
  revoked_at: Date | null;
  created_at: Date;
}

export class PasskeyRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public listForSubject(input: {
    tenantId: string | null;
    subjectId: string;
    subjectType: "CUSTOMER" | "ADMINISTRATOR";
    scope: "TENANT" | "PLATFORM";
  }): Promise<PasskeyRecord[]> {
    return this.transaction<PasskeyRecord>("user_passkeys")
      .where({
        subject_id: input.subjectId,
        subject_type: input.subjectType,
        scope_type: input.scope,
      })
      .whereNull("revoked_at")
      .whereNull("deleted_at")
      .modify((query) =>
        input.tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", input.tenantId),
      );
  }

  public findByCredentialForUpdate(
    credentialId: string,
    tenantId: string | null,
    scope: "TENANT" | "PLATFORM",
  ): Promise<PasskeyRecord | undefined> {
    return this.transaction<PasskeyRecord>("user_passkeys")
      .where({ credential_id: credentialId, scope_type: scope })
      .whereNull("revoked_at")
      .whereNull("deleted_at")
      .modify((query) =>
        tenantId === null
          ? query.whereNull("tenant_id")
          : query.where("tenant_id", tenantId),
      )
      .forUpdate()
      .first();
  }

  public async create(input: {
    tenantId: string | null;
    userId: string | null;
    subjectId: string;
    subjectType: "CUSTOMER" | "ADMINISTRATOR";
    scope: "TENANT" | "PLATFORM";
    credentialId: string;
    publicKey: string;
    relyingPartyId: string;
    aaguid: string;
    signCount: bigint;
    transports: string[];
    backupEligible: boolean;
    backupState: boolean;
    deviceType: string;
    friendlyName?: string;
  }): Promise<PasskeyRecord> {
    const [record] = await this.transaction<PasskeyRecord>("user_passkeys")
      .insert({
        tenant_id: input.tenantId,
        user_id: input.userId,
        subject_id: input.subjectId,
        subject_type: input.subjectType,
        scope_type: input.scope,
        credential_id: input.credentialId,
        public_key: input.publicKey,
        relying_party_id: input.relyingPartyId,
        aaguid: input.aaguid,
        sign_count: input.signCount.toString(),
        transports: input.transports,
        backup_eligible: input.backupEligible,
        backup_state: input.backupState,
        device_type: input.deviceType,
        friendly_name: input.friendlyName ?? null,
      })
      .returning("*");
    if (!record) throw new Error("Passkey insert returned no record");
    return record;
  }

  public async updateCounter(
    id: string,
    previousCounter: bigint,
    nextCounter: bigint,
    backupState: boolean,
  ): Promise<boolean> {
    const updated = await this.transaction("user_passkeys")
      .where({ id, sign_count: previousCounter.toString() })
      .update({
        sign_count: nextCounter.toString(),
        backup_state: backupState,
        last_used_at: this.transaction.fn.now(),
      });
    return updated === 1;
  }
}
