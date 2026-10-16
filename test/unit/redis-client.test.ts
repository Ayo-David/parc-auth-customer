import { loadConfig } from "../../src/config/env.js";
import { reconnectOnReadOnly, redisOptions } from "../../src/database/redis.js";

test("uses REDIS_URL directly when no sentinels are configured", () => {
  const options = redisOptions(loadConfig({ NODE_ENV: "test" }));
  expect(options.sentinels).toBeUndefined();
  expect(options.lazyConnect).toBe(true);
});

test("discovers the primary through Sentinel and follows failover", () => {
  const options = redisOptions(
    loadConfig({
      NODE_ENV: "test",
      REDIS_SENTINELS: "10.0.0.1, 10.0.0.2:6379,10.0.0.3:26379",
      REDIS_SENTINEL_MASTER_NAME: "parc-primary",
      REDIS_PASSWORD: "node-secret",
      REDIS_SENTINEL_PASSWORD: "sentinel-secret",
    }),
  );
  expect(options.sentinels).toEqual([
    { host: "10.0.0.1", port: 6379 },
    { host: "10.0.0.2", port: 6379 },
    { host: "10.0.0.3", port: 26379 },
  ]);
  expect(options).toMatchObject({
    name: "parc-primary",
    role: "master",
    failoverDetector: true,
    password: "node-secret",
    sentinelPassword: "sentinel-secret",
  });
});

test("rejects malformed sentinel endpoints", () => {
  expect(() =>
    loadConfig({ NODE_ENV: "test", REDIS_SENTINELS: "10.0.0.1:not-a-port" }),
  ).toThrow();
  expect(() =>
    loadConfig({ NODE_ENV: "test", REDIS_SENTINELS: ":6379" }),
  ).toThrow();
});

test("reconnects and resends when a demoted primary rejects writes", () => {
  expect(
    reconnectOnReadOnly(
      new Error("READONLY You can't write against a read only replica."),
    ),
  ).toBe(2);
  expect(reconnectOnReadOnly(new Error("WRONGTYPE Operation"))).toBe(false);
});
