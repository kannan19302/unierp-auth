// ─────────────────────────────────────────────────
// @kannan19302/auth — Authentication & RBAC
// ─────────────────────────────────────────────────
// This package provides authentication utilities and RBAC helpers.

import bcrypt from "bcryptjs";
import * as argon2 from "argon2";
import jwt from "jsonwebtoken";
import { createHash } from "node:crypto";

/**
 * Resolves the signing secret. Fails closed: there is no fallback value.
 *
 * A checked-in default secret is the same as no secret at all — anyone with
 * the source can mint a token that every service accepts. Resolution is lazy
 * so that importing this package (for its RBAC constants, say) does not
 * require a signing secret; only signing and verifying do.
 */
function getJwtSecret(): string {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) {
    throw new Error(
      "NEXTAUTH_SECRET is not set. Refusing to sign or verify tokens without a configured secret.",
    );
  }
  return secret;
}

const BCRYPT_ROUNDS = 12;

/**
 * Token purposes. Every token carries a `typ` claim and verification is
 * purpose-scoped, so a short-lived reset or MFA-challenge token can never be
 * replayed as a full session token.
 */
export const TOKEN_TYPE = {
  SESSION: "session",
  PASSWORD_RESET: "password-reset",
  MFA_CHALLENGE: "mfa-challenge",
  /** CSRF/state carrier for the OAuth authorization-code round-trip. */
  OAUTH_STATE: "oauth-state",
} as const;

export type TokenType = (typeof TOKEN_TYPE)[keyof typeof TOKEN_TYPE];

/**
 * Hashes a plaintext password using Argon2id.
 *
 * Argon2id is the OWASP-recommended password hashing algorithm (2024+).
 * It is resistant to both side-channel (Argon2i) and GPU/ASIC (Argon2d)
 * attacks. The parameters below follow the OWASP minimum recommendations:
 * - memoryCost: 19456 KiB (~19 MB)
 * - timeCost: 2 iterations
 * - parallelism: 1
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
}

/**
 * Whether a hash is a legacy bcrypt hash (starts with $2a$, $2b$, or $2y$).
 */
function isBcryptHash(hash: string): boolean {
  return hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$");
}

export interface PasswordVerifyResult {
  valid: boolean;
  /**
   * True if the hash is a legacy bcrypt hash that should be upgraded to
   * Argon2id. The caller is responsible for calling `hashPassword()` with
   * the plaintext and persisting the new hash. This enables transparent
   * read-time migration without a flag day.
   */
  needsRehash: boolean;
}

/**
 * Compares a plaintext password against a hash (Argon2id or legacy bcrypt).
 *
 * Transparent migration path:
 * - If the stored hash is Argon2id, verify directly.
 * - If the stored hash is bcrypt, verify with bcrypt and signal that a
 *   rehash to Argon2id is needed.
 *
 * Callers that don't need the migration signal can use the `valid` field only.
 */
export async function comparePassword(
  password: string,
  hash: string,
): Promise<boolean> {
  const result = await comparePasswordWithRehash(password, hash);
  return result.valid;
}

/**
 * Like comparePassword but returns the full result including rehash signal.
 * Used by the auth service's login path to trigger read-time hash upgrades.
 */
export async function comparePasswordWithRehash(
  password: string,
  hash: string,
): Promise<PasswordVerifyResult> {
  if (isBcryptHash(hash)) {
    const valid = await bcrypt.compare(password, hash);
    return { valid, needsRehash: valid };
  }
  // Argon2id hash — also check if parameters have changed
  const valid = await argon2.verify(hash, password);
  const needsRehash = valid ? argon2.needsRehash(hash, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  }) : false;
  return { valid, needsRehash };
}

/**
 * Checks a password against the HaveIBeenPwned Passwords API using
 * k-anonymity — only the first 5 hex chars of the SHA-1 are sent, so
 * the full password hash is never transmitted.
 *
 * Returns the breach count (0 = safe, >0 = compromised).
 * Returns -1 if the API is unreachable (fail open — do not block login).
 */
export async function checkPasswordBreach(
  password: string,
): Promise<number> {
  try {
    const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    const response = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        headers: { "Add-Padding": "true" },
        signal: AbortSignal.timeout(3000),
      },
    );

    if (!response.ok) return -1;

    const text = await response.text();
    const lines = text.split("\n");
    for (const line of lines) {
      const [hashSuffix, count] = line.trim().split(":");
      if (hashSuffix === suffix) {
        return parseInt(count || "0", 10);
      }
    }
    return 0;
  } catch {
    // Network failure — fail open so a HIBP outage doesn't block all logins.
    return -1;
  }
}

/**
 * Signs a JWT payload. Callers should prefer the purpose-scoped helpers below;
 * this remains for payloads that already carry their own `typ`.
 */
export function signToken(
  payload: string | object | Buffer,
  expiresIn: jwt.SignOptions["expiresIn"] = "1d",
): string {
  return jwt.sign(payload, getJwtSecret(), { expiresIn });
}

/**
 * Signs a token stamped with an explicit purpose.
 */
export function signTypedToken(
  type: TokenType,
  payload: Record<string, unknown>,
  expiresIn: jwt.SignOptions["expiresIn"],
): string {
  return jwt.sign({ ...payload, typ: type }, getJwtSecret(), { expiresIn });
}

export interface SessionTokenPayload extends Record<string, unknown> {
  sid: string;
  userId: string;
  tenantId: string | null;
  realm?: "tenant" | "provider";
  amr?: string[];
  mfaVerified?: boolean;
}

/**
 * Signs a full session token.
 */
export function signSessionToken(
  payload: SessionTokenPayload,
  expiresIn: jwt.SignOptions["expiresIn"] = "1d",
): string {
  return signTypedToken(TOKEN_TYPE.SESSION, payload, expiresIn);
}

/**
 * Verifies a JWT token and returns the decoded payload, or null if invalid.
 */
export function verifyToken(token: string): unknown {
  try {
    return jwt.verify(token, getJwtSecret());
  } catch {
    return null;
  }
}

/**
 * Verifies a token AND that it was issued for the given purpose. Returns null
 * on a bad signature, expiry, or a `typ` mismatch.
 *
 * Tokens minted before the `typ` claim existed are rejected rather than assumed
 * to be sessions — they expire within a day of deploy.
 */
export function verifyTypedToken<T = Record<string, unknown>>(
  token: string,
  type: TokenType,
): T | null {
  const payload = verifyToken(token);
  if (!payload || typeof payload !== "object") return null;
  if ((payload as { typ?: unknown }).typ !== type) return null;
  return payload as T;
}

export { hasPermission, parsePermission } from "@kannan19302/shared";

/**
 * System-level permission definitions.
 * Maps module names to their available resource permissions.
 */
export const SYSTEM_PERMISSIONS = {
  admin: {
    user: ["create", "read", "update", "delete"],
    role: ["create", "read", "update", "delete"],
    tenant: ["read", "update"],
    setting: ["read", "update"],
  },
  finance: {
    invoice: ["create", "read", "update", "delete", "send", "void"],
    payment: ["create", "read", "update", "delete"],
    account: ["create", "read", "update", "delete"],
    report: ["read", "export"],
  },
  hr: {
    employee: ["create", "read", "update", "delete"],
    department: ["create", "read", "update", "delete"],
    payroll: ["read", "create", "approve"],
    leave: ["create", "read", "approve"],
    attendance: ["read", "create", "update"],
  },
  crm: {
    contact: ["create", "read", "update", "delete"],
    lead: ["create", "read", "update", "delete", "convert"],
    opportunity: ["create", "read", "update", "delete"],
    activity: ["create", "read", "update", "delete"],
  },
  inventory: {
    product: ["create", "read", "update", "delete"],
    warehouse: ["create", "read", "update", "delete"],
    stock: ["read", "adjust", "transfer"],
  },
  procurement: {
    vendor: ["create", "read", "update", "delete"],
    "purchase-order": ["create", "read", "update", "delete", "approve"],
    rfq: ["create", "read", "update", "delete"],
  },
  sales: {
    quotation: ["create", "read", "update", "delete", "send"],
    "sales-order": ["create", "read", "update", "delete", "confirm"],
    return: ["create", "read", "update", "approve"],
  },
} as const;

/**
 * Default system roles with their permissions.
 */
export const DEFAULT_ROLES = {
  SUPER_ADMIN: {
    name: "Super Admin",
    description: "Full access to all features",
    permissions: ["*"],
    isSystem: true,
  },
  ADMIN: {
    name: "Admin",
    description: "Administrative access with user management",
    permissions: ["admin.*", "finance.*", "hr.*", "crm.*", "inventory.*"],
    isSystem: true,
  },
  FINANCE_MANAGER: {
    name: "Finance Manager",
    description: "Full access to finance module",
    permissions: ["finance.*", "sales.sales-order.read"],
    isSystem: true,
  },
  HR_MANAGER: {
    name: "HR Manager",
    description: "Full access to HR module",
    permissions: ["hr.*"],
    isSystem: true,
  },
  SALES_REP: {
    name: "Sales Representative",
    description: "Access to CRM and sales features",
    permissions: [
      "crm.*",
      "sales.quotation.*",
      "sales.sales-order.create",
      "sales.sales-order.read",
      "inventory.product.read",
    ],
    isSystem: true,
  },
  VIEWER: {
    name: "Viewer",
    description: "Read-only access to all modules",
    permissions: [
      "finance.invoice.read",
      "finance.report.read",
      "hr.employee.read",
      "crm.contact.read",
      "inventory.product.read",
    ],
    isSystem: true,
  },
} as const;

