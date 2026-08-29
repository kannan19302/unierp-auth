import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  decryptConfigurationSecret,
  encryptConfigurationSecret,
  isEncryptedConfigurationSecret,
} from "./configuration-secret";

describe("federation configuration secret envelope", () => {
  beforeEach(() => {
    process.env.SSO_CONFIG_ENCRYPTION_KEYS = JSON.stringify({
      current: Buffer.alloc(32, 7).toString("base64"),
      previous: Buffer.alloc(32, 8).toString("base64"),
    });
    process.env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID = "current";
  });

  afterEach(() => {
    delete process.env.SSO_CONFIG_ENCRYPTION_KEYS;
    delete process.env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID;
  });

  it("round-trips without embedding plaintext", () => {
    const plaintext = "synthetic-client-secret";
    const envelope = encryptConfigurationSecret(plaintext);
    expect(isEncryptedConfigurationSecret(envelope)).toBe(true);
    expect(envelope).not.toContain(plaintext);
    expect(decryptConfigurationSecret(envelope)).toBe(plaintext);
  });

  it("uses a fresh IV for the same value", () => {
    expect(encryptConfigurationSecret("same-synthetic-value")).not.toBe(
      encryptConfigurationSecret("same-synthetic-value"),
    );
  });

  it("rejects plaintext, tampering and an unavailable key", () => {
    expect(() => decryptConfigurationSecret("legacy-plaintext")).toThrow(/encrypted envelope/);
    const envelope = encryptConfigurationSecret("synthetic-client-secret");
    const tampered = `${envelope.slice(0, -1)}${envelope.endsWith("A") ? "B" : "A"}`;
    expect(() => decryptConfigurationSecret(tampered)).toThrow();
    process.env.SSO_CONFIG_ENCRYPTION_KEYS = JSON.stringify({
      current: Buffer.alloc(32, 9).toString("base64"),
    });
    expect(() => decryptConfigurationSecret(envelope)).toThrow();
  });

  it("decrypts a previous-key envelope during rotation and writes with the active key", () => {
    process.env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID = "previous";
    const previousEnvelope = encryptConfigurationSecret("synthetic-client-secret");
    expect(previousEnvelope).toMatch(/^enc:v1:previous:/);
    process.env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID = "current";
    expect(decryptConfigurationSecret(previousEnvelope)).toBe("synthetic-client-secret");
    expect(encryptConfigurationSecret("new-synthetic-secret")).toMatch(/^enc:v1:current:/);
  });

  it("fails closed when the key is absent or malformed", () => {
    delete process.env.SSO_CONFIG_ENCRYPTION_KEYS;
    expect(() => encryptConfigurationSecret("synthetic-client-secret")).toThrow(/required/);
    process.env.SSO_CONFIG_ENCRYPTION_KEYS = JSON.stringify({ current: "not-a-key" });
    expect(() => encryptConfigurationSecret("synthetic-client-secret")).toThrow(/32-byte/);
  });
});
