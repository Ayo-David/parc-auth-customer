import type { Knex } from "knex";
import type { ConsentDocument } from "../services/tenant-admin-client.js";

export class ConsentRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async grantAll(input: {
    tenantId: string;
    userId: string;
    documents: readonly ConsentDocument[];
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    const grantedAt = new Date();
    await this.transaction("user_consents").insert(
      input.documents.map((document) => ({
        tenant_id: input.tenantId,
        user_id: input.userId,
        consent_document_id: document.id,
        consent_type: document.consent_type,
        document_version: document.document_version,
        granted: true,
        granted_at: grantedAt,
        ip_address: input.ipAddress ?? null,
        user_agent: input.userAgent ?? null,
        purpose: document.purpose ?? null,
        channel: document.channel ?? null,
        policy_uri: document.policy_uri ?? null,
        evidence_digest: document.evidence_digest ?? null,
      })),
    );
  }

  public async hasActiveKycConsent(input: {
    consentId: string;
    userId: string;
  }): Promise<boolean> {
    const record = await this.transaction("user_consents")
      .where({
        user_id: input.userId,
        consent_type: "KYC",
        granted: true,
      })
      .andWhere((query) =>
        query
          .where("id", input.consentId)
          .orWhere("consent_document_id", input.consentId),
      )
      .whereNull("withdrawn_at")
      .whereNull("deleted_at")
      .first("id");
    return Boolean(record);
  }
}
