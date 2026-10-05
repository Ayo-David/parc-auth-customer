export type KycIdentityType = "NIN" | "BVN";
export type KycProviderName = "VERIFYME";
export type KycProviderOutcome =
  "VERIFIED" | "FAILED" | "PENDING" | "MANUAL_REVIEW";

export interface KycProviderResult {
  outcome: KycProviderOutcome;
  providerReference: string;
  providerConfigurationVersion: string;
  resultCode: string;
  safeResult: Record<string, unknown>;
}

export interface KycProvider {
  readonly name: KycProviderName;
  verifyIdentity(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    firstName?: string;
    lastName?: string;
  }): Promise<KycProviderResult>;
  verifyBiometric(input: {
    verificationId: string;
    identityType: KycIdentityType;
    identityValue: string;
    livenessReference: string;
  }): Promise<KycProviderResult>;
}

export interface KycProviderResolver {
  resolve(tenantId: string): Promise<KycProvider>;
}

export class StaticKycProviderResolver implements KycProviderResolver {
  public constructor(private readonly provider: KycProvider) {}

  public resolve(_tenantId: string): Promise<KycProvider> {
    return Promise.resolve(this.provider);
  }
}
