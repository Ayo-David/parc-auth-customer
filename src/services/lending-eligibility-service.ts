import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";

export class LendingEligibilityService {
  public constructor(private readonly database: Knex) {}

  public get(input: {
    tenantId: string;
    customerId: string;
    consentReference: string;
  }): Promise<Record<string, unknown>> {
    return withTenantTransaction(this.database, input.tenantId, async (tx) => {
      const customer = await tx("customer_profiles as c")
        .join("users as u", function () {
          this.on("u.id", "=", "c.user_id").andOn(
            "u.tenant_id",
            "=",
            "c.tenant_id",
          );
        })
        .where({
          "c.tenant_id": input.tenantId,
          "c.id": input.customerId,
        })
        .whereNull("c.deleted_at")
        .first("c.user_id", "u.status as customer_status");
      if (!customer)
        throw new ApiError(404, "CUSTOMER_NOT_FOUND", "Customer not found");
      const [tier, kyc, verification, risk, flags, consent] = await Promise.all(
        [
          tx("customer_kyc_tiers as t")
            .join("kyc_tier_versions as v", function () {
              this.on("v.id", "=", "t.kyc_tier_version_id").andOn(
                "v.tenant_id",
                "=",
                "t.tenant_id",
              );
            })
            .where({
              "t.tenant_id": input.tenantId,
              "t.customer_id": input.customerId,
            })
            .whereNull("t.effective_until")
            .whereNull("t.deleted_at")
            .orderBy("t.effective_from", "desc")
            .first("v.code", "v.version", "t.status", "t.updated_at"),
          tx("kyc_profiles")
            .where({ tenant_id: input.tenantId, customer_id: input.customerId })
            .whereNull("deleted_at")
            .first(
              "id",
              "status",
              "last_verified_at",
              "next_review_at",
              "updated_at",
            ),
          tx("kyc_verifications")
            .where({ tenant_id: input.tenantId, customer_id: input.customerId })
            .where("status", "VERIFIED")
            .orderBy("completed_at", "desc")
            .first(
              "id",
              "provider_reference",
              "provider_configuration_version",
              "completed_at",
            ),
          tx("customer_risk_profiles")
            .where({ tenant_id: input.tenantId, customer_id: input.customerId })
            .whereNull("deleted_at")
            .first(
              "id",
              "risk_level",
              "last_calculated_at",
              "calculation_version",
              "updated_at",
            ),
          tx("fraud_flags")
            .where({ tenant_id: input.tenantId, customer_id: input.customerId })
            .whereIn("status", ["FLAGGED", "UNDER_REVIEW", "BLOCKED"])
            .whereNull("deleted_at")
            .select(
              "id",
              "status",
              "severity",
              "source_reference",
              "updated_at",
            ),
          tx("user_consents")
            .where({
              tenant_id: input.tenantId,
              user_id: customer.user_id,
              id: input.consentReference,
              granted: true,
            })
            .whereNull("withdrawn_at")
            .whereNull("deleted_at")
            .first(
              "id",
              "consent_type",
              "document_version",
              "granted_at",
              "evidence_digest",
            ),
        ],
      );
      const blocked = flags.some(
        (flag: { status: string }) => flag.status === "BLOCKED",
      );
      const disposition = blocked
        ? "BLOCK"
        : flags.length > 0 ||
            !risk ||
            ["HIGH", "CRITICAL"].includes(String(risk.risk_level))
          ? "REFER"
          : "CLEAR";
      const observedAt = new Date().toISOString();
      return {
        customer_id: input.customerId,
        customer_status: customer.customer_status,
        kyc: {
          tier: tier?.code ?? "UNASSIGNED",
          tier_version: tier?.version ? String(tier.version) : "0",
          status: kyc?.status ?? "NOT_STARTED",
          verification_reference:
            verification?.provider_reference ?? verification?.id ?? null,
          provider_configuration_version:
            verification?.provider_configuration_version ?? null,
          observed_at: kyc?.last_verified_at ?? kyc?.updated_at ?? observedAt,
          expires_at: kyc?.next_review_at ?? null,
        },
        risk: {
          disposition,
          reason_codes: blocked
            ? ["ACTIVE_BLOCKING_RISK_FLAG"]
            : flags.length > 0
              ? ["ACTIVE_RISK_FLAG_REQUIRES_REVIEW"]
              : !risk
                ? ["RISK_ASSESSMENT_UNAVAILABLE"]
                : [],
          assessment_reference: risk?.id ?? null,
          assessment_version: risk?.calculation_version ?? "unversioned",
          observed_at:
            risk?.last_calculated_at ?? risk?.updated_at ?? observedAt,
        },
        consent: {
          reference: input.consentReference,
          valid: Boolean(consent),
          document_version: consent?.document_version ?? null,
          evidence_digest: consent?.evidence_digest ?? null,
          observed_at: consent?.granted_at ?? observedAt,
        },
      };
    });
  }
}
