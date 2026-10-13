export type KycIdentityType = "NIN" | "BVN";
export type KycProviderName = "VERIFYME" | "PREMBLY";
export type KycProviderOutcome =
  "VERIFIED" | "FAILED" | "PENDING" | "MANUAL_REVIEW";

/**
 * Registered identity details returned by the provider. Used once to fill the
 * customer profile and never stored with the provider result or evidence.
 */
export interface VerifiedIdentityAttributes {
  firstName?: string;
  middleName?: string;
  lastName?: string;
  /** ISO date, YYYY-MM-DD. */
  dateOfBirth?: string;
}

export interface KycProviderResult {
  outcome: KycProviderOutcome;
  providerReference: string;
  providerConfigurationVersion: string;
  resultCode: string;
  safeResult: Record<string, unknown>;
  identityAttributes?: VerifiedIdentityAttributes;
}

/** What the device captured for the face check; providers accept one or the other. */
export type FaceEvidence =
  | { kind: "LIVENESS_REFERENCE"; reference: string }
  | { kind: "SELFIE_IMAGE"; imageBase64: string };

export interface IdentityVerificationProvider {
  readonly name: KycProviderName;
  verifyIdentity(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    firstName?: string;
    lastName?: string;
  }): Promise<KycProviderResult>;
}

export interface FaceVerificationProvider {
  readonly name: KycProviderName;
  verifyFace(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    evidence: FaceEvidence;
  }): Promise<KycProviderResult>;
}

/** Identity lookup and face match are resolved separately so each can use its own provider. */
export interface KycProviderResolver {
  identity(tenantId: string): Promise<IdentityVerificationProvider>;
  face(tenantId: string): Promise<FaceVerificationProvider>;
}

export class StaticKycProviderResolver implements KycProviderResolver {
  public constructor(
    private readonly identityProvider: IdentityVerificationProvider,
    private readonly faceProvider: FaceVerificationProvider,
  ) {}

  public identity(_tenantId: string): Promise<IdentityVerificationProvider> {
    return Promise.resolve(this.identityProvider);
  }

  public face(_tenantId: string): Promise<FaceVerificationProvider> {
    return Promise.resolve(this.faceProvider);
  }
}

export function unsupportedFaceEvidence(
  providerReference: string,
  providerConfigurationVersion: string,
): KycProviderResult {
  return {
    outcome: "FAILED",
    providerReference,
    providerConfigurationVersion,
    resultCode: "FACE_EVIDENCE_UNSUPPORTED",
    safeResult: { status: "failed" },
  };
}
