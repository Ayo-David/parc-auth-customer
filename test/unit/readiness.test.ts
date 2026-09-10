import { checkReadiness } from "../../src/health/readiness.js";

test("reports a failed dependency without throwing", async () => {
  const result = await checkReadiness([
    { name: "database", check: async () => undefined },
    {
      name: "rabbitmq",
      check: async () => Promise.reject(new Error("offline")),
    },
  ]);
  expect(result).toEqual({
    ready: false,
    checks: { database: "UP", rabbitmq: "DOWN" },
  });
});
