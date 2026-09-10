import pino from "pino";
import request from "supertest";
import { createApp } from "../../src/app.js";
import { loadConfig } from "../../src/config/env.js";

const config = loadConfig({ NODE_ENV: "test", LOG_LEVEL: "silent" });
const logger = pino({ level: "silent" });

test("serves liveness and request IDs", async () => {
  const response = await request(createApp({ config, logger })).get("/health");
  expect(response.status).toBe(200);
  expect(response.headers["x-request-id"]).toBeDefined();
  expect(response.body).toEqual({
    status: "UP",
    service: "parc-auth-customer",
    version: "0.1.0",
  });
});

test("fails readiness when a required dependency is down", async () => {
  const app = createApp({
    config,
    logger,
    readinessChecks: [
      {
        name: "database",
        check: async () => Promise.reject(new Error("offline")),
      },
    ],
  });
  const response = await request(app).get("/ready");
  expect(response.status).toBe(503);
  expect(response.body).toEqual({
    status: "DOWN",
    ready: false,
    checks: { database: "DOWN" },
  });
});

test("returns a stable not-found error", async () => {
  const response = await request(createApp({ config, logger })).get("/missing");
  expect(response.status).toBe(404);
  expect(response.body).toEqual({
    code: "NOT_FOUND",
    message: "Resource not found",
  });
});
