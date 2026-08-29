import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";

const PREFIX = "enc:v1";
const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;

function decodeKey(encoded: string): Buffer {
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32 || key.toString("base64").replace(/=+$/, "") !== encoded.replace(/=+$/, "")) {
    throw new Error("Every SSO configuration encryption key must be a canonical base64-encoded 32-byte key.");
  }
  return key;
}

function keyring(): Map<string, Buffer> {
  const raw = process.env.SSO_CONFIG_ENCRYPTION_KEYS;
  if (!raw) throw new Error("SSO_CONFIG_ENCRYPTION_KEYS is required for federation secret encryption.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("SSO_CONFIG_ENCRYPTION_KEYS must be a JSON object of key IDs to base64 keys.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("SSO_CONFIG_ENCRYPTION_KEYS must be a JSON object of key IDs to base64 keys.");
  }
  const keys = new Map<string, Buffer>();
  for (const [id, value] of Object.entries(parsed)) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id) || typeof value !== "string") {
      throw new Error("SSO configuration encryption key IDs or values are invalid.");
    }
    keys.set(id, decodeKey(value));
  }
  if (keys.size === 0) throw new Error("SSO_CONFIG_ENCRYPTION_KEYS must contain at least one key.");
  return keys;
}

export function isEncryptedConfigurationSecret(value: string): boolean {
  return value.startsWith(`${PREFIX}:`);
}

/** Encrypt a federation configuration secret using an authenticated v1 envelope. */
export function encryptConfigurationSecret(plaintext: string): string {
  if (!plaintext) throw new Error("A non-empty federation secret is required.");
  const activeKeyId = process.env.SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID;
  if (!activeKeyId) throw new Error("SSO_CONFIG_ENCRYPTION_ACTIVE_KEY_ID is required.");
  const key = keyring().get(activeKeyId);
  if (!key) throw new Error("The active SSO configuration encryption key ID is not present in the keyring.");
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(Buffer.from(PREFIX, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, activeKeyId, iv.toString("base64url"), tag.toString("base64url"), ciphertext.toString("base64url")].join(":");
}

/**
 * Decrypt a v1 envelope. Plaintext and unknown versions fail closed so legacy
 * rows must be re-saved by an authorized tenant administrator before use.
 */
export function decryptConfigurationSecret(envelope: string): string {
  const [enc, version, keyId, ivValue, tagValue, ciphertextValue, extra] = envelope.split(":");
  if (enc !== "enc" || version !== "v1" || !keyId || !ivValue || !tagValue || !ciphertextValue || extra !== undefined) {
    throw new Error("Federation secret is not a supported encrypted envelope.");
  }
  const iv = Buffer.from(ivValue, "base64url");
  const tag = Buffer.from(tagValue, "base64url");
  const ciphertext = Buffer.from(ciphertextValue, "base64url");
  if (iv.length !== IV_BYTES || tag.length !== 16 || ciphertext.length === 0) {
    throw new Error("Federation secret envelope is malformed.");
  }
  const key = keyring().get(keyId);
  if (!key) throw new Error("Federation secret references an unavailable encryption key.");
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAAD(Buffer.from(PREFIX, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
