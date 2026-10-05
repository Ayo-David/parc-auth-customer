import { z } from "zod";
import type {
  KycIdentityType,
  KycProvider,
  KycProviderResult,
} from "./kyc-provider.js";

const verifyMeResponseSchema = z
  .object({
    status: z.string().optional(),
    data: z
      .object({
        id: z.union([z.string(), z.number()]).optional(),
        reference: z.union([z.string(), z.number()]).optional(),
        fieldMatches: z.record(z.boolean()).optional(),
      })
      .passthrough()
      .optional(),
    code: z.string().optional(),
    message: z.string().optional(),
  })
  .passthrough();

const livenessResponseSchema = z
  .object({
    isLive: z.boolean(),
    identityMatches: z.boolean(),
    identityDetails: z
      .object({ idNumber: z.string().optional() })
      .passthrough()
      .optional(),
  })
  .passthrough();

export interface VerifyMeProviderOptions {
  baseUrl: string;
  apiKey: string;
  configurationVersion: string;
  timeoutMs: number;
  fetchImplementation?: typeof fetch;
}

export class VerifyMeProvider implements KycProvider {
  public readonly name = "VERIFYME" as const;
  private readonly fetchImplementation: typeof fetch;

  public constructor(private readonly options: VerifyMeProviderOptions) {
    this.fetchImplementation = options.fetchImplementation ?? fetch;
  }

  public async verifyIdentity(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    firstName?: string;
    lastName?: string;
  }): Promise<KycProviderResult> {
    const fallbackReference = `verifyme-request:${input.verificationId}`;
    try {
      const response = await this.fetchImplementation(
        `${this.options.baseUrl}/v1/verifications/identities/${input.identityType.toLowerCase()}/${encodeURIComponent(input.identityValue)}?type=basic`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${this.options.apiKey}`,
            "content-type": "application/json",
            "x-correlation-id": input.verificationId,
          },
          body: JSON.stringify({
            ...(input.firstName ? { firstname: input.firstName } : {}),
            ...(input.lastName ? { lastname: input.lastName } : {}),
          }),
          signal: AbortSignal.timeout(this.options.timeoutMs),
        },
      );
      const payload = verifyMeResponseSchema.safeParse(
        await response.json().catch(() => ({})),
      );
      const parsed = payload.success ? payload.data : {};
      const providerReference = String(
        parsed.data?.reference ?? parsed.data?.id ?? fallbackReference,
      );
      if (response.ok && parsed.status?.toLowerCase() === "success")
        return {
          outcome: "VERIFIED",
          providerReference,
          providerConfigurationVersion: this.options.configurationVersion,
          resultCode: parsed.code ?? "SUCCESS",
          safeResult: {
            status: "success",
            ...(parsed.data?.fieldMatches
              ? { field_matches: parsed.data.fieldMatches }
              : {}),
          },
        };
      if (response.status === 400)
        return {
          outcome: "MANUAL_REVIEW",
          providerReference,
          providerConfigurationVersion: this.options.configurationVersion,
          resultCode: parsed.code ?? "INVALID_OR_INCOMPLETE_MATCHING_DATA",
          safeResult: { status: "manual_review" },
        };
      if (response.status === 404)
        return {
          outcome: "FAILED",
          providerReference,
          providerConfigurationVersion: this.options.configurationVersion,
          resultCode: parsed.code ?? `HTTP_${String(response.status)}`,
          safeResult: { status: "failed" },
        };
      return this.pending(fallbackReference, `HTTP_${String(response.status)}`);
    } catch {
      return this.pending(fallbackReference, "PROVIDER_OUTCOME_UNKNOWN");
    }
  }

  public async verifyBiometric(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    livenessReference: string;
  }): Promise<KycProviderResult> {
    const fallbackReference = `verifyme-biometric:${input.verificationId}`;
    try {
      const response = await this.fetchImplementation(
        `${this.options.baseUrl}/v1/verifications/liveness/${encodeURIComponent(input.livenessReference)}`,
        {
          method: "GET",
          headers: {
            authorization: `Bearer ${this.options.apiKey}`,
            "x-correlation-id": input.verificationId,
          },
          signal: AbortSignal.timeout(this.options.timeoutMs),
        },
      );
      const payload = livenessResponseSchema.safeParse(
        await response.json().catch(() => ({})),
      );
      const parsed: z.infer<typeof livenessResponseSchema> | undefined =
        payload.success ? payload.data : undefined;
      const providerReference = input.livenessReference;
      // The face must match the identity being verified, not whichever one the
      // client bound to the liveness session.
      const identityConfirmed =
        parsed?.identityDetails?.idNumber === input.identityValue;
      if (
        response.ok &&
        parsed?.isLive &&
        parsed.identityMatches &&
        identityConfirmed
      )
        return {
          outcome: "VERIFIED",
          providerReference,
          providerConfigurationVersion: this.options.configurationVersion,
          resultCode: "LIVENESS_AND_FACE_MATCHED",
          safeResult: {
            status: "success",
            liveness_verified: true,
            face_matched: true,
          },
        };
      if (response.ok || response.status === 400)
        return {
          outcome: "FAILED",
          providerReference,
          providerConfigurationVersion: this.options.configurationVersion,
          resultCode: "LIVENESS_OR_FACE_NOT_MATCHED",
          safeResult: {
            status: "failed",
            liveness_verified: parsed?.isLive === true,
            face_matched: parsed?.identityMatches === true && identityConfirmed,
          },
        };
      return this.pending(fallbackReference, `HTTP_${String(response.status)}`);
    } catch {
      return this.pending(fallbackReference, "PROVIDER_OUTCOME_UNKNOWN");
    }
  }

  private pending(
    providerReference: string,
    resultCode: string,
  ): KycProviderResult {
    return {
      outcome: "PENDING",
      providerReference,
      providerConfigurationVersion: this.options.configurationVersion,
      resultCode,
      safeResult: { status: "pending" },
    };
  }
}
