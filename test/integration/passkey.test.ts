import { randomUUID } from "node:crypto";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";
import knex, { type Knex } from "knex";
import { withTenantTransaction } from "../../src/database/transaction.js";
import { UserRepository } from "../../src/repositories/user-repository.js";
import { MemoryOtpSecretStore } from "../../src/security/otp-secret-store.js";
import { createJwtKeyRing } from "../../src/security/jwt-key-ring.js";
import type { AuthResultIssuer } from "../../src/services/authentication-service.js";
import {
  PasskeyService,
  type WebAuthnAdapter,
} from "../../src/services/passkey-service.js";
import { SessionService } from "../../src/services/session-service.js";
import type { AdministratorTenantAdminClient } from "../../src/services/tenant-admin-client.js";

const databaseUrl = process.env.TEST_DATABASE_URL;
const integrationTest = databaseUrl ? test : test.skip;
let database: Knex;

beforeAll(() => {
  database = knex({
    client: "pg",
    connection: databaseUrl ?? "postgresql:///unused",
  });
});
afterAll(async () => database.destroy());

const registrationResponse = {
  id: "credential-one",
  rawId: "credential-one",
  type: "public-key",
  clientExtensionResults: {},
  response: { clientDataJSON: "client", attestationObject: "attestation" },
} as RegistrationResponseJSON;
const authenticationResponse = {
  id: "credential-one",
  rawId: "credential-one",
  type: "public-key",
  clientExtensionResults: {},
  response: {
    clientDataJSON: "client",
    authenticatorData: "authenticator",
    signature: "signature",
  },
} as AuthenticationResponseJSON;

integrationTest(
  "registers and authenticates a tenant-bound passkey once",
  async () => {
    const tenantId = randomUUID();
    const user = await withTenantTransaction(
      database,
      tenantId,
      (transaction) =>
        new UserRepository(transaction).create({
          tenantId,
          phone: "+2348099999999",
          phoneNormalized: "+2348099999999",
          status: "ACTIVE",
        }),
    );
    const policy = {
      customer_mfa_required: false,
      allowed_customer_mfa_methods: ["PASSKEY" as const],
      passkey: {
        relying_party_id: "app.parc.test",
        relying_party_name: "Parc Test",
        allowed_origins: ["https://app.parc.test"],
      },
      version: 1,
    };
    const tenantAdmin: AdministratorTenantAdminClient = {
      verifyAdministrator: async () => {
        throw new Error("unused");
      },
      getAdministratorAuthorization: async () => ({
        roles: [],
        permissions: [],
        authorization_version: 1,
      }),
      getTenantAuthenticationPolicy: async () => policy,
      getPlatformAuthenticationPolicy: async () => policy,
      consumeApproval: async () => {
        throw new Error("unused");
      },
    };
    let nextCounter = 1;
    let registrationSequence = 0;
    let authenticationSequence = 0;
    const adapter: WebAuthnAdapter = {
      registrationOptions: async () =>
        ({
          challenge: `registration-challenge-${String(++registrationSequence)}`,
        }) as PublicKeyCredentialCreationOptionsJSON,
      authenticationOptions: async () => ({
        challenge: `authentication-challenge-${String(++authenticationSequence)}`,
      }),
      verifyRegistration: async (input) => {
        expect(input).toMatchObject({
          expectedChallenge: expect.stringMatching(
            /^registration-challenge-[12]$/,
          ),
          expectedOrigin: ["https://app.parc.test"],
          expectedRPID: "app.parc.test",
          requireUserVerification: true,
        });
        return {
          verified: true,
          registrationInfo: {
            fmt: "none",
            aaguid: "00000000-0000-0000-0000-000000000000",
            credential: {
              id: "credential-one",
              publicKey: new Uint8Array([1, 2, 3]),
              counter: 0,
              transports: ["internal"],
            },
            credentialType: "public-key",
            attestationObject: new Uint8Array(),
            userVerified: true,
            credentialDeviceType: "singleDevice",
            credentialBackedUp: false,
            origin: "https://app.parc.test",
            rpID: "app.parc.test",
          },
        };
      },
      verifyAuthentication: async (input) => {
        expect(input).toMatchObject({
          expectedChallenge: expect.stringMatching(
            /^authentication-challenge-[12]$/,
          ),
          expectedOrigin: ["https://app.parc.test"],
          expectedRPID: "app.parc.test",
          requireUserVerification: true,
        });
        return {
          verified: true,
          authenticationInfo: {
            credentialID: "credential-one",
            newCounter: nextCounter,
            userVerified: true,
            credentialDeviceType: "singleDevice",
            credentialBackedUp: false,
            origin: "https://app.parc.test",
            rpID: "app.parc.test",
          },
        };
      },
    };
    const issuer: AuthResultIssuer = {
      issue: async (input) => ({
        subject: input.userId,
        methods: input.authenticationMethods,
      }),
    };
    const sessionService = new SessionService(
      database,
      await createJwtKeyRing({ activeKid: "passkey-test-key" }),
      "https://auth.parc.invalid",
      "t".repeat(32),
      tenantAdmin,
    );
    const service = new PasskeyService(
      database,
      tenantAdmin,
      new MemoryOtpSecretStore(),
      issuer,
      sessionService,
      "c".repeat(32),
      adapter,
    );

    const registration = await service.createCustomerRegistrationOptions(
      tenantId,
      user.id,
      "My phone",
    );
    await expect(
      service.verifyRegistration({
        tenantId,
        scope: "TENANT",
        challengeId: registration.challenge_id,
        credential: registrationResponse,
      }),
    ).resolves.toMatchObject({
      credential_id: "credential-one",
      friendly_name: "My phone",
    });

    const authentication = await service.createAuthenticationOptions({
      tenantId,
      scope: "TENANT",
      identifier: "+2348099999999",
    });
    await expect(
      service.verifyAuthentication({
        tenantId,
        scope: "TENANT",
        challengeId: authentication.challenge_id,
        credential: authenticationResponse,
        idempotencyKey: randomUUID(),
      }),
    ).resolves.toMatchObject({ subject: user.id, methods: ["PASSKEY"] });
    await expect(
      service.verifyAuthentication({
        tenantId,
        scope: "TENANT",
        challengeId: authentication.challenge_id,
        credential: authenticationResponse,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "PASSKEY_CHALLENGE_INVALID" });

    const replayCounter = await service.createAuthenticationOptions({
      tenantId,
      scope: "TENANT",
      identifier: "+2348099999999",
    });
    nextCounter = 1;
    await expect(
      service.verifyAuthentication({
        tenantId,
        scope: "TENANT",
        challengeId: replayCounter.challenge_id,
        credential: authenticationResponse,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "PASSKEY_COUNTER_REPLAY" });

    const otherTenant = randomUUID();
    const crossTenant = await service.createCustomerRegistrationOptions(
      tenantId,
      user.id,
    );
    await expect(
      service.verifyRegistration({
        tenantId: otherTenant,
        scope: "TENANT",
        challengeId: crossTenant.challenge_id,
        credential: registrationResponse,
      }),
    ).rejects.toMatchObject({ code: "PASSKEY_CHALLENGE_INVALID" });

    await database("authentication_challenges")
      .where({ tenant_id: tenantId })
      .delete();
    await database("user_passkeys").where({ tenant_id: tenantId }).delete();
    await database("users").where({ id: user.id }).delete();
  },
);
