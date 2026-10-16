import { jest } from "@jest/globals";
import { checkRedisWritable } from "../../src/health/redis.js";

test("probes Redis with an expiring write", async () => {
  const set = jest.fn<() => Promise<string>>().mockResolvedValue("OK");
  await checkRedisWritable({ set });
  expect(set).toHaveBeenCalledWith(
    "parc-auth-customer:readiness:probe",
    expect.any(String),
    "EX",
    30,
  );
});

test("fails when Redis rejects writes, as a read-only replica does", async () => {
  const set = jest
    .fn<() => Promise<string>>()
    .mockRejectedValue(
      new Error("READONLY You can't write against a read only replica."),
    );
  await expect(checkRedisWritable({ set })).rejects.toThrow("READONLY");
});
