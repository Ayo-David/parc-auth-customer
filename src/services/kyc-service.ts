import { createHash, createHmac, randomUUID } from "node:crypto";
import type { Knex } from "knex";
import { ApiError } from "../http/api-error.js";
import { withTenantTransaction } from "../database/transaction.js";
import { ConsentRepository } from "../repositories/consent-repository.js";
import { CustomerRepository } from "../repositories/customer-repository.js";
import {
  KycRepository,
  type KycVerificationRecord,
} from "../repositories/kyc-repository.js";
import { IdempotencyRepository } from "../repositories/idempotency-repository.js";
import { EventRepository } from "../repositories/event-repository.js";
import type {
  KycIdentityType,
  KycProviderResolver,
  KycProviderResult,
} from "../providers/kyc-provider.js";

export interface KycVerificationView {
  id: string;
  identity_type: KycIdentityType;
  masked_identity: string;
  provider: "VERIFYME";
  status: "PENDING" | "VERIFIED" | "FAILED" | "MANUAL_REVIEW";
  created_at: string;
}

export interface StartKycVerificationInput {
  tenantId: string;
  userId: string;
  identityType: KycIdentityType;
  identityValue: string;
  consentId: string;
  idempotencyKey: string;
  correlationId: string;
}

export interface KycEvidenceKeys {
  identifierHashSecret: string;
  identifierHashKeyId: string;
  resultSigningSecret: string;
  resultSigningKeyId: string;
}

function maskIdentity(value: string): string {
  return `${"*".repeat(Math.max(0, value.length - 4))}${value.slice(-4)}`;
}

function publicStatus(
  status: KycVerificationRecord["status"],
): KycVerificationView["status"] {
  if (status === "VERIFIED") return "VERIFIED";
  if (status === "REJECTED") return "FAILED";
  if (status === "REQUIRES_REVIEW") return "MANUAL_REVIEW";
  return "PENDING";
}

function toView(
  record: KycVerificationRecord,
  maskedIdentity?: string,
): KycVerificationView {
  const storedMasked = record.metadata.masked_identity;
  return {
    id: record.id,
    identity_type: record.verification_type,
    masked_identity:
      maskedIdentity ??
      (typeof storedMasked === "string" ? storedMasked : "*******"),
    provider: record.provider_name,
    status: publicStatus(record.status),
    created_at: record.requested_at.toISOString(),
  };
}

export class KycService {
  public constructor(
    private readonly database: Knex,
    private readonly providers: KycProviderResolver,
    private readonly idempotencySecret: string,
    private readonly evidenceKeys: KycEvidenceKeys,
  ) {}

  public async start(
    input: StartKycVerificationInput,
  ): Promise<KycVerificationView> {
    const provider = await this.providers.resolve(input.tenantId);
    const maskedIdentity = maskIdentity(input.identityValue);
    const identifierHash = createHmac(
      "sha256",
      this.evidenceKeys.identifierHashSecret,
    )
      .update(`${input.tenantId}:${input.identityType}:${input.identityValue}`)
      .digest("hex");
    const requestHash = createHmac("sha256", this.idempotencySecret)
      .update(
        JSON.stringify({
          userId: input.userId,
          identityType: input.identityType,
          identifierHash,
          consentId: input.consentId,
          provider: provider.name,
        }),
      )
      .digest("hex");
    const verificationId = randomUUID();

    const initial = await withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const idempotency = new IdempotencyRepository(transaction);
        const claim = await idempotency.claim({
          tenantId: input.tenantId,
          key: input.idempotencyKey,
          operation: "kyc.identity.verify",
          requestHash,
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
        });
        if (!claim.created) {
          if (claim.record.status === "COMPLETED")
            return {
              replay: claim.record.response_body as KycVerificationView,
            };
          throw new ApiError(
            409,
            "REQUEST_IN_PROGRESS",
            "An equivalent KYC request is in progress",
          );
        }
        const customer = await new CustomerRepository(transaction).findByUserId(
          input.userId,
        );
        if (!customer)
          throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
        if (
          !(await new ConsentRepository(transaction).hasActiveKycConsent({
            consentId: input.consentId,
            userId: input.userId,
          }))
        )
          throw new ApiError(
            422,
            "KYC_CONSENT_REQUIRED",
            "Active KYC consent is required",
          );
        const record = await new KycRepository(transaction).create({
          verificationId,
          tenantId: input.tenantId,
          customerId: customer.id,
          consentId: input.consentId,
          identityType: input.identityType,
          providerName: provider.name,
        });
        await transaction("kyc_verifications")
          .where({ id: record.id })
          .update({ metadata: { masked_identity: maskedIdentity } });
        return {
          customerId: customer.id,
          ...(customer.first_name ? { firstName: customer.first_name } : {}),
          ...(customer.last_name ? { lastName: customer.last_name } : {}),
        };
      },
    );
    if ("replay" in initial) return initial.replay;

    const providerResult = await provider.verifyIdentity({
      verificationId,
      identityType: input.identityType,
      identityValue: input.identityValue,
      ...(initial.firstName ? { firstName: initial.firstName } : {}),
      ...(initial.lastName ? { lastName: initial.lastName } : {}),
    });
    return withTenantTransaction(
      this.database,
      input.tenantId,
      async (transaction) => {
        const repository = new KycRepository(transaction);
        const record = await repository.recordProviderResult({
          verificationId,
          ...providerResult,
        });
        if (providerResult.outcome === "VERIFIED")
          await repository.recordEvidence({
            tenantId: input.tenantId,
            verificationId,
            consentId: input.consentId,
            identityType: input.identityType,
            identifierMasked: maskedIdentity,
            identifierHash,
            hashKeyId: this.evidenceKeys.identifierHashKeyId,
            providerReference: providerResult.providerReference,
            providerConfigurationVersion:
              providerResult.providerConfigurationVersion,
            ...this.signResult(providerResult),
            retainUntil: new Date(Date.now() + 5 * 365 * 24 * 60 * 60 * 1000),
          });
        await repository.updateProfile({
          tenantId: input.tenantId,
          customerId: initial.customerId,
          outcome: providerResult.outcome,
        });
        await this.publishStatusChanged(
          transaction,
          input,
          initial.customerId,
          record,
        );
        const response = toView(record, maskedIdentity);
        await new IdempotencyRepository(transaction).complete({
          tenantId: input.tenantId,
          key: input.idempotencyKey,
          operation: "kyc.identity.verify",
          responseCode: 202,
          responseBody: response,
        });
        return response;
      },
    );
  }

  public get(
    tenantId: string,
    userId: string,
    verificationId: string,
  ): Promise<KycVerificationView> {
    return withTenantTransaction(
      this.database,
      tenantId,
      async (transaction) => {
        const record = await new KycRepository(transaction).findByIdForUser(
          verificationId,
          tenantId,
          userId,
        );
        if (!record)
          throw new ApiError(
            404,
            "KYC_VERIFICATION_NOT_FOUND",
            "KYC verification not found",
          );
        return toView(record);
      },
    );
  }

  private signResult(result: KycProviderResult): {
    resultDigest: string;
    resultSignature: string;
    signingKeyId: string;
  } {
    const canonicalResult = JSON.stringify({
      outcome: result.outcome,
      providerReference: result.providerReference,
      providerConfigurationVersion: result.providerConfigurationVersion,
      resultCode: result.resultCode,
      safeResult: result.safeResult,
    });
    const resultDigest = createHash("sha256")
      .update(canonicalResult)
      .digest("hex");
    return {
      resultDigest,
      resultSignature: createHmac(
        "sha256",
        this.evidenceKeys.resultSigningSecret,
      )
        .update(resultDigest)
        .digest("hex"),
      signingKeyId: this.evidenceKeys.resultSigningKeyId,
    };
  }

  private async publishStatusChanged(
    transaction: Knex.Transaction,
    input: StartKycVerificationInput,
    customerId: string,
    record: KycVerificationRecord,
  ): Promise<void> {
    const eventId = randomUUID();
    await new EventRepository(transaction).publish({
      tenantId: input.tenantId,
      eventId,
      eventType: "customer.kyc-status-changed.v1",
      aggregateType: "customer",
      aggregateId: customerId,
      payload: {
        event_id: eventId,
        event_type: "customer.kyc-status-changed.v1",
        event_version: 1,
        occurred_at: new Date().toISOString(),
        producer: "parc-auth-customer",
        tenant_id: input.tenantId,
        aggregate_type: "customer",
        aggregate_id: customerId,
        aggregate_version: 1,
        correlation_id: input.correlationId,
        causation_id: null,
        idempotency_key: input.idempotencyKey,
        data_classification: "CONFIDENTIAL",
        payload: {
          customer_id: customerId,
          status: publicStatus(record.status),
          kyc_tier: 0,
        },
      },
    });
  }
}
