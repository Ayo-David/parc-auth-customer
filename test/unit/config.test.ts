import { loadConfig } from "../../src/config/env.js";

test("loads safe defaults", () => {
  const config = loadConfig({ NODE_ENV: "test" });
  expect(config.PORT).toBe(3001);
  expect(config.SERVICE_NAME).toBe("parc-auth-customer");
});

test("rejects invalid ports", () => {
  expect(() => loadConfig({ PORT: "70000" })).toThrow();
});

test("selects KYC providers per capability", () => {
  const config = loadConfig({
    NODE_ENV: "test",
    KYC_IDENTITY_PROVIDER: "VERIFYME",
    KYC_FACE_PROVIDER: "PREMBLY",
  });
  expect(config.KYC_IDENTITY_PROVIDER).toBe("VERIFYME");
  expect(config.KYC_FACE_PROVIDER).toBe("PREMBLY");
  expect(() =>
    loadConfig({ NODE_ENV: "test", KYC_FACE_PROVIDER: "UNKNOWN" }),
  ).toThrow();
  expect(() =>
    loadConfig({ NODE_ENV: "test", PREMBLY_FACE_MATCH_THRESHOLD: "50" }),
  ).toThrow();
});

test("parses outbox tenants and requires them when publishing", () => {
  const tenantId = "7b0b0cde-2f6e-4f0a-9d25-7f3c2a3b1c11";
  expect(
    loadConfig({
      NODE_ENV: "test",
      OUTBOX_PUBLISHER_ENABLED: "true",
      OUTBOX_TENANT_IDS: ` ${tenantId} ,`,
    }).OUTBOX_TENANT_IDS,
  ).toEqual([tenantId]);
  expect(() =>
    loadConfig({ NODE_ENV: "test", OUTBOX_PUBLISHER_ENABLED: "true" }),
  ).toThrow("OUTBOX_PUBLISHER_ENABLED requires OUTBOX_TENANT_IDS");
  expect(() =>
    loadConfig({ NODE_ENV: "test", OUTBOX_TENANT_IDS: "not-a-uuid" }),
  ).toThrow();
});

test("requires a real Prembly key in production only when Prembly is selected", () => {
  const messages = (environment: NodeJS.ProcessEnv) => {
    try {
      loadConfig({ NODE_ENV: "production", ...environment });
      return [];
    } catch (error) {
      return (error as { issues: { message: string }[] }).issues.map(
        (issue) => issue.message,
      );
    }
  };
  expect(messages({})).toContain("Production requires PREMBLY_API_KEY");
  expect(
    messages({
      KYC_IDENTITY_PROVIDER: "VERIFYME",
      KYC_FACE_PROVIDER: "VERIFYME",
    }),
  ).not.toContain("Production requires PREMBLY_API_KEY");
  expect(messages({ PREMBLY_API_KEY: "live-key" })).not.toContain(
    "Production requires PREMBLY_API_KEY",
  );
});

test("strips trailing slashes from provider base URLs", () => {
  const config = loadConfig({
    NODE_ENV: "test",
    TERMII_BASE_URL: "https://v4.api.termii.com/",
    PREMBLY_BASE_URL: "https://api.prembly.com//",
  });
  expect(config.TERMII_BASE_URL).toBe("https://v4.api.termii.com");
  expect(config.PREMBLY_BASE_URL).toBe("https://api.prembly.com");
});

test("defaults SMS to Robase and requires only the selected SMS provider's key in production", () => {
  const messages = (environment: NodeJS.ProcessEnv) => {
    try {
      loadConfig({ NODE_ENV: "production", ...environment });
      return [];
    } catch (error) {
      return (error as { issues: { message: string }[] }).issues.map(
        (issue) => issue.message,
      );
    }
  };
  expect(loadConfig({ NODE_ENV: "test" }).SMS_PROVIDER).toBe("ROBASE");
  expect(messages({})).toContain("Production requires ROBASE_API_KEY");
  expect(messages({})).not.toContain("Production requires TERMII_API_KEY");
  expect(messages({ ROBASE_API_KEY: "robe_live" })).not.toContain(
    "Production requires ROBASE_API_KEY",
  );
  const termii = messages({ SMS_PROVIDER: "TERMII" });
  expect(termii).toContain("Production requires TERMII_API_KEY");
  expect(termii).not.toContain("Production requires ROBASE_API_KEY");
  expect(() =>
    loadConfig({ NODE_ENV: "test", SMS_PROVIDER: "TWILIO" }),
  ).toThrow();
});
