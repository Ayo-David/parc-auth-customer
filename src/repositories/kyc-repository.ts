import type { Knex } from "knex";
import type {
  KycIdentityType,
  KycProviderName,
  KycProviderOutcome,
} from "../providers/kyc-provider.js";

export type KycDatabaseStatus =
  "PENDING" | "IN_PROGRESS" | "VERIFIED" | "REJECTED" | "REQUIRES_REVIEW";

export interface KycVerificationRecord {
  id: string;
  tenant_id: string;
  customer_id: string;
  verification_type: KycIdentityType | "BIOMETRIC";
  provider_name: KycProviderName;
  provider_reference: string | null;
  provider_configuration_version: string | null;
  status: KycDatabaseStatus;
  requested_at: Date;
  completed_at: Date | null;
  failure_reason: string | null;
  consent_id: string;
  metadata: Record<string, unknown>;
}

function databaseStatus(outcome: KycProviderOutcome): KycDatabaseStatus {
  if (outcome === "VERIFIED") return "VERIFIED";
  if (outcome === "FAILED") return "REJECTED";
  if (outcome === "MANUAL_REVIEW") return "REQUIRES_REVIEW";
  return "PENDING";
}

export class KycRepository {
  public constructor(private readonly transaction: Knex.Transaction) {}

  public async create(input: {
    verificationId: string;
    tenantId: string;
    customerId: string;
    consentId: string;
    identityType: KycIdentityType | "BIOMETRIC";
    providerName: KycProviderName;
  }): Promise<KycVerificationRecord> {
    const [record] = await this.transaction<KycVerificationRecord>(
      "kyc_verifications",
    )
      .insert({
        id: input.verificationId,
        tenant_id: input.tenantId,
        customer_id: input.customerId,
        consent_id: input.consentId,
        verification_type: input.identityType,
        provider_name: input.providerName,
        status: "PENDING",
        metadata: {},
      })
      .returning("*");
    if (!record) throw new Error("KYC verification insert returned no record");
    return record;
  }

  public findById(id: string): Promise<KycVerificationRecord | undefined> {
    return this.transaction<KycVerificationRecord>("kyc_verifications")
      .where({ id })
      .first();
  }

  public findByIdForUser(
    id: string,
    tenantId: string,
    userId: string,
  ): Promise<KycVerificationRecord | undefined> {
    return this.transaction<KycVerificationRecord>("kyc_verifications as kv")
      .join("customer_profiles as cp", "cp.id", "kv.customer_id")
      .where("kv.id", id)
      .where("kv.tenant_id", tenantId)
      .where("cp.tenant_id", tenantId)
      .where("cp.user_id", userId)
      .whereNull("cp.deleted_at")
      .select("kv.*")
      .first();
  }

  public async recordProviderResult(input: {
    verificationId: string;
    providerReference: string;
    providerConfigurationVersion: string;
    outcome: KycProviderOutcome;
    resultCode: string;
    safeResult: Record<string, unknown>;
  }): Promise<KycVerificationRecord> {
    const status = databaseStatus(input.outcome);
    const [record] = await this.transaction<KycVerificationRecord>(
      "kyc_verifications",
    )
      .where({ id: input.verificationId, status: "PENDING" })
      .update({
        provider_reference: input.providerReference,
        provider_configuration_version: input.providerConfigurationVersion,
        status,
        completed_at:
          input.outcome === "PENDING" ? null : this.transaction.fn.now(),
        failure_reason: input.outcome === "FAILED" ? input.resultCode : null,
      })
      .returning("*");
    if (!record) throw new Error("KYC verification finalization failed");
    await this.transaction("kyc_verification_results").insert({
      tenant_id: record.tenant_id,
      verification_id: record.id,
      result_code: input.resultCode,
      result_status: status,
      response_data: input.safeResult,
    });
    return record;
  }

  public async recordEvidence(input: {
    tenantId: string;
    verificationId: string;
    consentId: string;
    identityType: KycIdentityType;
    identifierMasked: string;
    identifierHash: string;
    hashKeyId: string;
    providerReference: string;
    providerConfigurationVersion: string;
    resultDigest: string;
    resultSignature: string;
    signingKeyId: string;
    retainUntil: Date;
  }): Promise<void> {
    await this.transaction("identity_verification_evidence").insert({
      tenant_id: input.tenantId,
      verification_id: input.verificationId,
      consent_id: input.consentId,
      identifier_type: input.identityType,
      identifier_masked: input.identifierMasked,
      identifier_hash: input.identifierHash,
      hash_key_id: input.hashKeyId,
      provider_reference: input.providerReference,
      provider_configuration_version: input.providerConfigurationVersion,
      result_digest: input.resultDigest,
      result_signature: input.resultSignature,
      signing_key_id: input.signingKeyId,
      verified_at: this.transaction.fn.now(),
      retain_until: input.retainUntil,
    });
  }

  public async updateProfile(input: {
    tenantId: string;
    customerId: string;
    outcome: KycProviderOutcome;
  }): Promise<void> {
    if (input.outcome === "PENDING") return;
    const status = databaseStatus(input.outcome);
    const existing = await this.transaction("kyc_profiles")
      .where({ customer_id: input.customerId })
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .first("id");
    if (existing)
      await this.transaction("kyc_profiles")
        .where({ id: existing.id })
        .update({
          status,
          last_verified_at:
            input.outcome === "VERIFIED" ? this.transaction.fn.now() : null,
          rejection_reason:
            input.outcome === "FAILED" ? "IDENTITY_VERIFICATION_FAILED" : null,
          updated_at: this.transaction.fn.now(),
        });
    else
      await this.transaction("kyc_profiles").insert({
        tenant_id: input.tenantId,
        customer_id: input.customerId,
        status,
        last_verified_at:
          input.outcome === "VERIFIED" ? this.transaction.fn.now() : null,
        rejection_reason:
          input.outcome === "FAILED" ? "IDENTITY_VERIFICATION_FAILED" : null,
      });
  }
}
