import argon2 from "argon2";
import knex from "knex";
import { z } from "zod";

const config = z
  .object({
    NODE_ENV: z.enum(["development", "test"]),
    DATABASE_URL: z.string().url(),
    PR01_TENANT_A_ID: z.string().uuid(),
    PR01_TENANT_B_ID: z.string().uuid(),
    PR01_CUSTOMER_PASSWORD: z.string().min(12),
    PR01_CUSTOMER_PASSCODE: z.string().regex(/^\d{6}$/),
  })
  .parse(process.env);

const database = knex({ client: "pg", connection: config.DATABASE_URL });
const fixtures = [
  {
    tenantId: config.PR01_TENANT_A_ID,
    userId: "11111111-1111-4111-8111-111111111101",
    customerId: "11111111-1111-4111-8111-111111111102",
    passwordCredentialId: "11111111-1111-4111-8111-111111111103",
    passcodeCredentialId: "11111111-1111-4111-8111-111111111104",
    phone: "+2348020000001",
    email: "customer-alpha@pr01.parc.invalid",
    customerNumber: "PR01-A-000001",
    firstName: "Ada",
    lastName: "Alpha",
  },
  {
    tenantId: config.PR01_TENANT_B_ID,
    userId: "22222222-2222-4222-8222-222222222201",
    customerId: "22222222-2222-4222-8222-222222222202",
    passwordCredentialId: "22222222-2222-4222-8222-222222222203",
    passcodeCredentialId: "22222222-2222-4222-8222-222222222204",
    phone: "+2348020000002",
    email: "customer-beta@pr01.parc.invalid",
    customerNumber: "PR01-B-000001",
    firstName: "Bola",
    lastName: "Beta",
  },
] as const;

try {
  const passwordHash = await argon2.hash(config.PR01_CUSTOMER_PASSWORD);
  const passcodeHash = await argon2.hash(config.PR01_CUSTOMER_PASSCODE);

  await database.transaction(async (transaction) => {
    for (const fixture of fixtures) {
      await transaction("users")
        .insert({
          id: fixture.userId,
          tenant_id: fixture.tenantId,
          user_type: "CUSTOMER",
          status: "ACTIVE",
          phone: fixture.phone,
          phone_normalized: fixture.phone,
          phone_verified: true,
          phone_verified_at: transaction.fn.now(),
          email: fixture.email,
          email_normalized: fixture.email,
          email_verified: true,
          email_verified_at: transaction.fn.now(),
          metadata: JSON.stringify({ fixture: "PR-01", disposable: true }),
        })
        .onConflict("id")
        .merge({
          status: "ACTIVE",
          phone: fixture.phone,
          phone_normalized: fixture.phone,
          email: fixture.email,
          email_normalized: fixture.email,
          updated_at: transaction.fn.now(),
        });

      await transaction("customer_profiles")
        .insert({
          id: fixture.customerId,
          tenant_id: fixture.tenantId,
          user_id: fixture.userId,
          customer_number: fixture.customerNumber,
          first_name: fixture.firstName,
          last_name: fixture.lastName,
          metadata: JSON.stringify({ fixture: "PR-01", disposable: true }),
        })
        .onConflict("id")
        .merge({
          first_name: fixture.firstName,
          last_name: fixture.lastName,
          updated_at: transaction.fn.now(),
        });

      const credentials = [
        {
          id: fixture.passwordCredentialId,
          credentialType: "PASSWORD",
          credentialHash: passwordHash,
        },
        {
          id: fixture.passcodeCredentialId,
          credentialType: "LOGIN_PASSCODE",
          credentialHash: passcodeHash,
        },
      ] as const;

      for (const credential of credentials) {
        const [existing] = await transaction<{
          id: string;
          user_id: string;
          credential_type: string;
        }>("user_credentials")
          .where({
            user_id: fixture.userId,
            credential_type: credential.credentialType,
          })
          .whereNull("deleted_at")
          .select("id")
          .limit(1);
        if (existing === undefined)
          await transaction("user_credentials").insert({
            id: credential.id,
            tenant_id: fixture.tenantId,
            user_id: fixture.userId,
            credential_type: credential.credentialType,
            credential_hash: credential.credentialHash,
          });
      }
    }
  });

  console.log(
    JSON.stringify({
      fixture: "PR-01",
      customers: fixtures.map(({ tenantId, userId, customerId, phone }) => ({
        tenantId,
        userId,
        customerId,
        phone,
      })),
    }),
  );
} finally {
  await database.destroy();
}
