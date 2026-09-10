import { z } from "zod";
import { ApiError } from "../http/api-error.js";

const consentType = z.enum([
  "TERMS_AND_CONDITIONS",
  "PRIVACY_POLICY",
  "DATA_PROCESSING",
  "KYC",
  "CREDIT_CHECK",
  "MARKETING",
  "BIOMETRIC",
  "OPEN_BANKING",
  "DIRECT_DEBIT",
]);

const tenantStatusSchema = z.object({
  tenant_id: z.string().uuid(),
  status: z.enum(["PENDING_APPROVAL", "ACTIVE", "SUSPENDED", "CLOSED"]),
});

const consentDocumentSchema = z.object({
  id: z.string().uuid(),
  tenant_id: z.string().uuid(),
  consent_type: consentType,
  document_version: z.string().min(1).max(50),
  purpose: z.string().max(150).optional(),
  channel: z.string().max(30).optional(),
  policy_uri: z.string().url().optional(),
  evidence_digest: z.string().max(128).optional(),
});

const administratorVerificationSchema = z.object({
  administrator_id: z.string().uuid(),
  tenant_id: z.string().uuid().nullable(),
  scope: z.enum(["TENANT", "PLATFORM"]),
  status: z.enum(["ACTIVE", "SUSPENDED", "DISABLED"]),
  roles: z.array(z.string()),
  authorization_version: z.number().int().positive(),
  mfa_required: z.boolean(),
  allowed_mfa_methods: z.array(
    z.enum(["TOTP", "SMS_OTP", "EMAIL_OTP", "PASSKEY"]),
  ),
});
const administratorAuthorizationSchema = z.object({
  roles: z.array(z.string()),
  permissions: z.array(z.string()),
  authorization_version: z.number().int().positive(),
});
const tenantAuthenticationPolicySchema = z.object({
  customer_mfa_required: z.boolean(),
  allowed_customer_mfa_methods: z.array(
    z.enum(["TOTP", "SMS_OTP", "EMAIL_OTP", "PASSKEY"]),
  ),
  passkey: z
    .object({
      relying_party_id: z.string().min(1).max(255),
      relying_party_name: z.string().min(1).max(100),
      allowed_origins: z.array(z.string().url()).min(1),
    })
    .nullable(),
  version: z.number().int().positive(),
});

export type AdministratorVerification = z.infer<
  typeof administratorVerificationSchema
>;
export type AdministratorAuthorization = z.infer<
  typeof administratorAuthorizationSchema
>;
export type TenantAuthenticationPolicy = z.infer<
  typeof tenantAuthenticationPolicySchema
>;

export type ConsentDocument = z.infer<typeof consentDocumentSchema>;

export interface TenantAdminClient {
  validateRegistration(
    tenantId: string,
    consentIds: readonly string[],
    idempotencyKey: string,
  ): Promise<readonly ConsentDocument[]>;
}

export interface AdministratorTenantAdminClient {
  verifyAdministrator(input: {
    identifier: string;
    password: string;
    tenantContext: string | null;
    idempotencyKey: string;
  }): Promise<AdministratorVerification>;
  getAdministratorAuthorization(
    administratorId: string,
  ): Promise<AdministratorAuthorization>;
  getTenantAuthenticationPolicy(
    tenantId: string,
  ): Promise<TenantAuthenticationPolicy>;
  getPlatformAuthenticationPolicy(): Promise<TenantAuthenticationPolicy>;
  consumeApproval(input: {
    approvalId: string;
    tenantId: string | null;
    idempotencyKey: string;
    action: string;
    resourceId: string;
    payloadHash: string;
  }): Promise<void>;
}

export class HttpTenantAdminClient
  implements TenantAdminClient, AdministratorTenantAdminClient
{
  public constructor(
    private readonly baseUrl: string,
    private readonly serviceToken: string,
  ) {}

  public async validateRegistration(
    tenantId: string,
    consentIds: readonly string[],
    idempotencyKey: string,
  ): Promise<readonly ConsentDocument[]> {
    const headers = { authorization: `Bearer ${this.serviceToken}` };
    const statusResponse = await fetch(
      `${this.baseUrl}/internal/v1/tenants/${tenantId}/status`,
      { headers },
    );
    if (!statusResponse.ok)
      throw new ApiError(422, "TENANT_UNAVAILABLE", "Tenant is unavailable");
    const status = tenantStatusSchema.parse(await statusResponse.json());
    if (status.tenant_id !== tenantId || status.status !== "ACTIVE")
      throw new ApiError(422, "TENANT_INACTIVE", "Tenant is not active");

    const consentResponse = await fetch(
      `${this.baseUrl}/internal/v1/tenants/${tenantId}/consent-documents/validate`,
      {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "idempotency-key": idempotencyKey,
        },
        body: JSON.stringify({ consent_ids: consentIds }),
      },
    );
    if (!consentResponse.ok)
      throw new ApiError(
        422,
        "INVALID_CONSENT_DOCUMENTS",
        "One or more consent documents are invalid",
      );
    const documents = z
      .array(consentDocumentSchema)
      .parse(await consentResponse.json());
    if (
      documents.length !== consentIds.length ||
      documents.some(
        (document) =>
          document.tenant_id !== tenantId || !consentIds.includes(document.id),
      )
    )
      throw new ApiError(
        422,
        "INVALID_CONSENT_DOCUMENTS",
        "Consent document validation was incomplete",
      );
    return documents;
  }

  public async verifyAdministrator(input: {
    identifier: string;
    password: string;
    tenantContext: string | null;
    idempotencyKey: string;
  }): Promise<AdministratorVerification> {
    const response = await fetch(
      `${this.baseUrl}/internal/v1/admin-auth/verify`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.serviceToken}`,
          "content-type": "application/json",
          "idempotency-key": input.idempotencyKey,
        },
        body: JSON.stringify({
          identifier: input.identifier,
          password: input.password,
          tenant_context: input.tenantContext,
        }),
      },
    );
    if (!response.ok)
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    const result = administratorVerificationSchema.parse(await response.json());
    if (
      result.status !== "ACTIVE" ||
      (result.scope === "TENANT" && result.tenant_id !== input.tenantContext) ||
      (result.scope === "PLATFORM" && result.tenant_id !== null)
    )
      throw new ApiError(401, "AUTHENTICATION_FAILED", "Authentication failed");
    return result;
  }

  public async getAdministratorAuthorization(
    administratorId: string,
  ): Promise<AdministratorAuthorization> {
    const response = await fetch(
      `${this.baseUrl}/internal/v1/admins/${administratorId}/authorization`,
      { headers: { authorization: `Bearer ${this.serviceToken}` } },
    );
    if (!response.ok)
      throw new ApiError(401, "AUTHORIZATION_STALE", "Authorization changed");
    return administratorAuthorizationSchema.parse(await response.json());
  }

  public async getTenantAuthenticationPolicy(
    tenantId: string,
  ): Promise<TenantAuthenticationPolicy> {
    const response = await fetch(
      `${this.baseUrl}/internal/v1/tenants/${tenantId}/authentication-policy`,
      { headers: { authorization: `Bearer ${this.serviceToken}` } },
    );
    if (!response.ok)
      throw new ApiError(
        422,
        "TENANT_POLICY_UNAVAILABLE",
        "Tenant policy is unavailable",
      );
    return tenantAuthenticationPolicySchema.parse(await response.json());
  }

  public async getPlatformAuthenticationPolicy(): Promise<TenantAuthenticationPolicy> {
    const response = await fetch(
      `${this.baseUrl}/internal/v1/platform/authentication-policy`,
      { headers: { authorization: `Bearer ${this.serviceToken}` } },
    );
    if (!response.ok)
      throw new ApiError(
        422,
        "PLATFORM_POLICY_UNAVAILABLE",
        "Platform policy is unavailable",
      );
    return tenantAuthenticationPolicySchema.parse(await response.json());
  }

  public async consumeApproval(input: {
    approvalId: string;
    tenantId: string | null;
    idempotencyKey: string;
    action: string;
    resourceId: string;
    payloadHash: string;
  }): Promise<void> {
    const path = input.tenantId
      ? `/internal/v1/approvals/${input.approvalId}/consume`
      : `/internal/v1/platform/approvals/${input.approvalId}/consume`;
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.serviceToken}`,
        "content-type": "application/json",
        "idempotency-key": input.idempotencyKey,
        ...(input.tenantId ? { "x-tenant-id": input.tenantId } : {}),
      },
      body: JSON.stringify({
        action: input.action,
        resource_id: input.resourceId,
        payload_hash: input.payloadHash,
      }),
    });
    if (!response.ok)
      throw new ApiError(
        403,
        "APPROVAL_INVALID",
        "Approval is invalid or already consumed",
      );
  }
}
