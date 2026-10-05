import { createHmac, randomUUID } from "node:crypto";
import argon2 from "argon2";
import type { Knex } from "knex";
import { withTenantTransaction } from "../database/transaction.js";
import { ApiError } from "../http/api-error.js";
import { ConsentRepository } from "../repositories/consent-repository.js";
import { CredentialRepository } from "../repositories/credential-repository.js";
import { CustomerRepository } from "../repositories/customer-repository.js";
import { IdempotencyRepository } from "../repositories/idempotency-repository.js";
import { UserRepository } from "../repositories/user-repository.js";
import type { TenantAdminClient } from "./tenant-admin-client.js";

type Step =
  | "PHONE_VERIFICATION"
  | "EMAIL"
  | "IDENTITY"
  | "FACE_VERIFICATION"
  | "ADDRESS"
  | "COMPLIANCE"
  | "INCOME"
  | "LOGIN_PASSCODE"
  | "BIOMETRIC"
  | "COMPLETED";

interface SessionRecord {
  id: string;
  user_id: string;
  customer_id: string;
  status: "IN_PROGRESS" | "COMPLETED" | "EXPIRED";
  current_step: Step;
  completed_steps: Step[];
  expires_at: Date;
  completed_at: Date | null;
  updated_at: Date;
}

export class OnboardingService {
  public constructor(
    private readonly database: Knex,
    private readonly tenantAdmin: TenantAdminClient,
    private readonly idempotencySecret: string,
  ) {}

  public async start(input: {
    tenantId: string;
    idempotencyKey: string;
    phoneNumber: string;
    consentIds: readonly string[];
    referralCode?: string;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<{
    onboarding_id: string;
    customer_id: string;
    current_step: Step;
  }> {
    const phone = input.phoneNumber.trim();
    const documents = await this.tenantAdmin.validateRegistration(
      input.tenantId,
      input.consentIds,
      input.idempotencyKey,
    );
    const hash = this.fingerprint({
      phone,
      consents: [...input.consentIds].sort(),
      referralCode: input.referralCode ?? null,
    });
    return withTenantTransaction(this.database, input.tenantId, async (tx) => {
      const idempotency = new IdempotencyRepository(tx);
      const claim = await idempotency.claim({
        tenantId: input.tenantId,
        key: input.idempotencyKey,
        operation: "mobile-onboarding.start",
        requestHash: hash,
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      });
      if (!claim.created) {
        if (claim.record.status === "COMPLETED")
          return claim.record.response_body as {
            onboarding_id: string;
            customer_id: string;
            current_step: Step;
          };
        throw new ApiError(
          409,
          "REQUEST_IN_PROGRESS",
          "Onboarding request is in progress",
        );
      }
      const users = new UserRepository(tx);
      const existing = await users.findByCanonicalIdentifier(
        input.tenantId,
        phone,
      );
      let user: { id: string };
      let profile: { id: string };
      if (existing) {
        // Only a customer whose unfinished onboarding lapsed may start again.
        const lapsed = await tx<SessionRecord>("customer_onboarding_sessions")
          .where({ user_id: existing.id, status: "IN_PROGRESS" })
          .where("expires_at", "<=", tx.fn.now())
          .orderBy("created_at", "desc")
          .first();
        if (!lapsed)
          throw new ApiError(
            409,
            "CUSTOMER_ALREADY_EXISTS",
            "A customer with these details already exists",
          );
        await tx("customer_onboarding_sessions")
          .where({ id: lapsed.id })
          .update({ status: "EXPIRED" });
        user = existing;
        profile = { id: lapsed.customer_id };
        await new ConsentRepository(tx).grantAll({
          tenantId: input.tenantId,
          userId: user.id,
          documents,
          ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
          ...(input.userAgent ? { userAgent: input.userAgent } : {}),
        });
      } else {
        user = await users.create({
          tenantId: input.tenantId,
          phone,
          phoneNormalized: phone,
        });
        profile = await new CustomerRepository(tx).create({
          tenantId: input.tenantId,
          userId: user.id,
          customerNumber: `CUS-${randomUUID().replaceAll("-", "").toUpperCase()}`,
        });
        await new ConsentRepository(tx).grantAll({
          tenantId: input.tenantId,
          userId: user.id,
          documents,
          ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
          ...(input.userAgent ? { userAgent: input.userAgent } : {}),
        });
        if (input.referralCode)
          await this.attachReferral(
            tx,
            input.tenantId,
            user.id,
            input.referralCode,
          );
      }
      const [session] = (await tx("customer_onboarding_sessions")
        .insert({
          tenant_id: input.tenantId,
          user_id: user.id,
          customer_id: profile.id,
        })
        .returning("*")) as SessionRecord[];
      if (!session)
        throw new Error("Onboarding session insert returned no record");
      const result = {
        onboarding_id: session.id,
        customer_id: profile.id,
        current_step: session.current_step,
      };
      await idempotency.complete({
        tenantId: input.tenantId,
        key: input.idempotencyKey,
        operation: "mobile-onboarding.start",
        responseCode: 201,
        responseBody: result,
      });
      return result;
    });
  }

  /** Customer access tokens carry the profile ID; onboarding rows key on users.id. */
  public userIdForCustomer(
    tenantId: string,
    customerId: string,
  ): Promise<string> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const profile = await new CustomerRepository(tx).findById(customerId);
      if (!profile)
        throw new ApiError(401, "UNAUTHORIZED", "Authentication failed");
      return profile.user_id;
    });
  }

  public status(tenantId: string, userId: string): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      return this.view(session);
    });
  }

  public updateEmail(
    tenantId: string,
    userId: string,
    email?: string,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "EMAIL");
      if (email) {
        await new UserRepository(tx).updateEmail({
          id: userId,
          email,
          emailNormalized: email,
        });
        return this.view(session);
      }
      return this.advance(tx, session, "EMAIL", "IDENTITY");
    });
  }

  public updateAddress(
    tenantId: string,
    userId: string,
    input: Record<string, string | undefined>,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "ADDRESS");
      await tx("customer_addresses").insert({
        tenant_id: tenantId,
        customer_id: session.customer_id,
        address_type: "RESIDENTIAL",
        address_line_1: input.street_address,
        state: input.state,
        city: input.area,
        lga: input.lga,
        area: input.area,
        landmark: input.landmark ?? null,
        is_primary: true,
      });
      return this.advance(tx, session, "ADDRESS", "COMPLIANCE");
    });
  }

  public updateCompliance(
    tenantId: string,
    userId: string,
    pep: boolean,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "COMPLIANCE");
      await tx("aml_profiles")
        .insert({
          tenant_id: tenantId,
          customer_id: session.customer_id,
          pep_status: pep,
        })
        .onConflict(["customer_id"])
        .merge({ pep_status: pep, updated_at: tx.fn.now() });
      return this.advance(tx, session, "COMPLIANCE", "INCOME");
    });
  }

  public updateIncome(
    tenantId: string,
    userId: string,
    input: {
      occupation: string;
      annualIncomeBand: string;
      hasOtherIncome: boolean;
    },
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "INCOME");
      await tx("customer_profiles").where({ id: session.customer_id }).update({
        occupation: input.occupation,
        annual_income_band: input.annualIncomeBand,
        has_other_income: input.hasOtherIncome,
        updated_at: tx.fn.now(),
      });
      return this.advance(tx, session, "INCOME", "LOGIN_PASSCODE");
    });
  }

  public async setLoginPasscode(
    tenantId: string,
    userId: string,
    passcode: string,
  ): Promise<object> {
    const passcodeHash = await argon2.hash(passcode, {
      type: argon2.argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1,
    });
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "LOGIN_PASSCODE");
      await new CredentialRepository(tx).replace({
        tenantId,
        userId,
        type: "LOGIN_PASSCODE",
        hash: passcodeHash,
        reason: "ONBOARDING_SETUP",
      });
      await tx("users")
        .where({ id: userId })
        .update({ status: "ACTIVE", updated_at: tx.fn.now() });
      return this.advance(tx, session, "LOGIN_PASSCODE", "BIOMETRIC");
    });
  }

  public markPhoneVerified(tenantId: string, userId: string): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) =>
      this.advance(
        tx,
        await this.session(tx, userId),
        "PHONE_VERIFICATION",
        "EMAIL",
      ),
    );
  }

  public markPhoneVerifiedBySession(
    tenantId: string,
    onboardingId: string,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await tx<SessionRecord>("customer_onboarding_sessions")
        .where({ id: onboardingId })
        .first();
      if (!session)
        throw new ApiError(
          404,
          "ONBOARDING_NOT_FOUND",
          "Onboarding session not found",
        );
      this.requireStep(session, "PHONE_VERIFICATION");
      const user = await tx("users")
        .where({ id: session.user_id, phone_verified: true })
        .first("id");
      if (!user)
        throw new ApiError(
          422,
          "PHONE_NOT_VERIFIED",
          "Phone verification has not completed",
        );
      return this.advance(tx, session, "PHONE_VERIFICATION", "EMAIL");
    });
  }

  public markEmailVerified(tenantId: string, userId: string): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "EMAIL");
      const user = await tx("users")
        .where({ id: session.user_id, email_verified: true })
        .whereNotNull("email")
        .first("id");
      if (!user)
        throw new ApiError(
          422,
          "EMAIL_NOT_VERIFIED",
          "Email verification has not completed",
        );
      return this.advance(tx, session, "EMAIL", "IDENTITY");
    });
  }

  public markIdentity(
    tenantId: string,
    userId: string,
    verified: boolean,
  ): Promise<object> {
    if (!verified)
      throw new ApiError(
        422,
        "IDENTITY_NOT_VERIFIED",
        "Identity verification has not completed",
      );
    return withTenantTransaction(this.database, tenantId, async (tx) =>
      this.advance(
        tx,
        await this.session(tx, userId),
        "IDENTITY",
        "FACE_VERIFICATION",
      ),
    );
  }

  public markFaceVerified(tenantId: string, userId: string): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) =>
      this.advance(
        tx,
        await this.session(tx, userId),
        "FACE_VERIFICATION",
        "ADDRESS",
      ),
    );
  }

  public confirmFaceVerification(
    tenantId: string,
    userId: string,
    verificationId: string,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "FACE_VERIFICATION");
      const evidence = await tx("kyc_verifications")
        .where({
          id: verificationId,
          customer_id: session.customer_id,
          verification_type: "BIOMETRIC",
          status: "VERIFIED",
        })
        .first("id");
      if (!evidence)
        throw new ApiError(
          422,
          "FACE_NOT_VERIFIED",
          "Verified face evidence is required",
        );
      return this.advance(tx, session, "FACE_VERIFICATION", "ADDRESS");
    });
  }

  public completeBiometric(
    tenantId: string,
    userId: string,
    enrolled: boolean,
  ): Promise<object> {
    return withTenantTransaction(this.database, tenantId, async (tx) => {
      const session = await this.session(tx, userId);
      this.requireStep(session, "BIOMETRIC");
      if (enrolled) {
        const passkey = await tx("user_passkeys")
          .where({ user_id: userId, status: "ACTIVE" })
          .whereNull("deleted_at")
          .first("id");
        if (!passkey)
          throw new ApiError(
            422,
            "PASSKEY_NOT_ENROLLED",
            "An active passkey is required",
          );
      }
      const steps = [
        ...new Set([
          ...session.completed_steps,
          ...(enrolled ? ["BIOMETRIC" as Step] : []),
        ]),
      ];
      const [updated] = (await tx("customer_onboarding_sessions")
        .where({ id: session.id })
        .update({
          status: "COMPLETED",
          current_step: "COMPLETED",
          completed_steps: JSON.stringify(steps),
          completed_at: tx.fn.now(),
        })
        .returning("*")) as SessionRecord[];
      return this.view(updated ?? session);
    });
  }

  private async session(
    tx: Knex.Transaction,
    userId: string,
  ): Promise<SessionRecord> {
    const record = await tx<SessionRecord>("customer_onboarding_sessions")
      .where({ user_id: userId })
      .whereNot({ status: "EXPIRED" })
      .orderBy("created_at", "desc")
      .first();
    if (!record)
      throw new ApiError(
        404,
        "ONBOARDING_NOT_FOUND",
        "Onboarding session not found",
      );
    if (record.expires_at.getTime() <= Date.now())
      throw new ApiError(
        410,
        "ONBOARDING_EXPIRED",
        "Onboarding session expired",
      );
    return record;
  }

  private async advance(
    tx: Knex.Transaction,
    session: SessionRecord,
    completed: Step,
    next: Step,
  ): Promise<object> {
    if (session.completed_steps.includes(completed)) return this.view(session);
    this.requireStep(session, completed);
    const steps = [...new Set([...session.completed_steps, completed])];
    const [updated] = (await tx("customer_onboarding_sessions")
      .where({ id: session.id })
      .update({ current_step: next, completed_steps: JSON.stringify(steps) })
      .returning("*")) as SessionRecord[];
    if (!updated) throw new Error("Onboarding update returned no record");
    return this.view(updated);
  }

  private requireStep(session: SessionRecord, expected: Step): void {
    if (session.current_step !== expected)
      throw new ApiError(
        409,
        "ONBOARDING_STEP_OUT_OF_ORDER",
        `Complete ${session.current_step} before ${expected}`,
      );
  }

  private view(session: SessionRecord): object {
    return {
      onboarding_id: session.id,
      status: session.status,
      current_step: session.current_step,
      completed_steps: session.completed_steps,
      expires_at: session.expires_at.toISOString(),
      completed_at: session.completed_at?.toISOString() ?? null,
      updated_at: session.updated_at.toISOString(),
    };
  }

  private fingerprint(value: object): string {
    return createHmac("sha256", this.idempotencySecret)
      .update(JSON.stringify(value))
      .digest("hex");
  }

  private async attachReferral(
    tx: Knex.Transaction,
    tenantId: string,
    userId: string,
    code: string,
  ): Promise<void> {
    const referrer = await tx("users")
      .where({ tenant_id: tenantId, referral_code: code })
      .whereNull("deleted_at")
      .first("id");
    if (!referrer)
      throw new ApiError(
        422,
        "INVALID_REFERRAL_CODE",
        "Referral code is invalid",
      );
    const program = await tx("referral_programs")
      .where({ tenant_id: tenantId, is_active: true })
      .whereNull("deleted_at")
      .orderBy("created_at", "desc")
      .first("id");
    if (!program)
      throw new ApiError(
        422,
        "REFERRAL_PROGRAM_UNAVAILABLE",
        "Referral program is unavailable",
      );
    await tx("referrals").insert({
      tenant_id: tenantId,
      program_id: program.id,
      referrer_user_id: referrer.id,
      referred_user_id: userId,
      referral_code: code,
    });
  }
}
