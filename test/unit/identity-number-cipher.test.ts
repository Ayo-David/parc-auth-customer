import { randomBytes } from "node:crypto";
import { IdentityNumberCipher } from "../../src/security/identity-number-cipher.js";

const owner = {
  tenantId: "11111111-1111-4111-8111-111111111111",
  customerId: "22222222-2222-4222-8222-222222222222",
  identityType: "BVN" as const,
};
const key = () => randomBytes(32).toString("base64");

test("round-trips a BVN without storing it in the clear", () => {
  const cipher = new IdentityNumberCipher("v1", { v1: key() });
  const encrypted = cipher.encrypt("22222222222", owner);
  expect(encrypted.keyId).toBe("v1");
  expect(JSON.stringify(encrypted)).not.toContain("22222222222");
  expect(cipher.decrypt(encrypted, owner)).toBe("22222222222");
});

test("uses a fresh IV each time", () => {
  const cipher = new IdentityNumberCipher("v1", { v1: key() });
  const first = cipher.encrypt("22222222222", owner);
  const second = cipher.encrypt("22222222222", owner);
  expect(first.iv).not.toBe(second.iv);
  expect(first.ciphertext).not.toBe(second.ciphertext);
});

test("refuses a ciphertext moved onto another customer", () => {
  const cipher = new IdentityNumberCipher("v1", { v1: key() });
  const encrypted = cipher.encrypt("22222222222", owner);
  expect(() =>
    cipher.decrypt(encrypted, {
      ...owner,
      customerId: "33333333-3333-4333-8333-333333333333",
    }),
  ).toThrow();
});

test("still decrypts rows written under a retired key", () => {
  const retired = key();
  const old = new IdentityNumberCipher("v1", { v1: retired });
  const encrypted = old.encrypt("22222222222", owner);
  const rotated = new IdentityNumberCipher("v2", { v1: retired, v2: key() });
  expect(rotated.decrypt(encrypted, owner)).toBe("22222222222");
  expect(rotated.encrypt("22222222222", owner).keyId).toBe("v2");
});

test("rejects keys that aren't 32 bytes", () => {
  expect(
    () =>
      new IdentityNumberCipher("v1", {
        v1: Buffer.from("short").toString("base64"),
      }),
  ).toThrow("32 bytes");
});
