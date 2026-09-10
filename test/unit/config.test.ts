import { loadConfig } from "../../src/config/env.js";

test("loads safe defaults", () => {
  const config = loadConfig({ NODE_ENV: "test" });
  expect(config.PORT).toBe(3001);
  expect(config.SERVICE_NAME).toBe("parc-auth-customer");
});

test("rejects invalid ports", () => {
  expect(() => loadConfig({ PORT: "70000" })).toThrow();
});
