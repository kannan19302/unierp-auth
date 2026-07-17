// ─────────────────────────────────────────────────
// @unerp/auth — Authentication & RBAC
// ─────────────────────────────────────────────────
// This package provides authentication utilities and RBAC helpers.

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

function getJwtSecret(): string {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) {
    throw new Error('NEXTAUTH_SECRET environment variable is required — never run with a default secret.');
  }
  return secret;
}

const JWT_SECRET: string = getJwtSecret();

const BCRYPT_ROUNDS = 12;

/**
 * Token purposes. Every token carries a `typ` claim and verification is
 * purpose-scoped, so a short-lived reset or MFA-challenge token can never be
 * replayed as a full session token.
 */
export const TOKEN_TYPE = {
  SESSION: 'session',
  PASSWORD_RESET: 'password-reset',
  MFA_CHALLENGE: 'mfa-challenge',
} as const;

export type TokenType = (typeof TOKEN_TYPE)[keyof typeof TOKEN_TYPE];

/**
 * Hashes a plaintext password using bcrypt.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Compares a plaintext password against a bcrypt hash.
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Signs a JWT payload. Callers should prefer the purpose-scoped helpers below;
 * this remains for payloads that already carry their own `typ`.
 */
export function signToken(
  payload: string | object | Buffer,
  expiresIn: jwt.SignOptions['expiresIn'] = '1d',
): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

/**
 * Signs a token stamped with an explicit purpose.
 */
export function signTypedToken(
  type: TokenType,
  payload: Record<string, unknown>,
  expiresIn: jwt.SignOptions['expiresIn'],
): string {
  return jwt.sign({ ...payload, typ: type }, JWT_SECRET, { expiresIn });
}

/**
 * Signs a full session token.
 */
export function signSessionToken(
  payload: Record<string, unknown>,
  expiresIn: jwt.SignOptions['expiresIn'] = '1d',
): string {
  return signTypedToken(TOKEN_TYPE.SESSION, payload, expiresIn);
}

/**
 * Verifies a JWT token and returns the decoded payload, or null if invalid.
 */
export function verifyToken(token: string): unknown {
  try {
    return jwt.verify(token, JWT_SECRET);
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
  if (!payload || typeof payload !== 'object') return null;
  if ((payload as { typ?: unknown }).typ !== type) return null;
  return payload as T;
}

export { hasPermission, parsePermission } from '@unerp/shared';

/**
 * System-level permission definitions.
 * Maps module names to their available resource permissions.
 */
export const SYSTEM_PERMISSIONS = {
  admin: {
    user: ['create', 'read', 'update', 'delete'],
    role: ['create', 'read', 'update', 'delete'],
    tenant: ['read', 'update'],
    setting: ['read', 'update'],
  },
  finance: {
    invoice: ['create', 'read', 'update', 'delete', 'send', 'void'],
    payment: ['create', 'read', 'update', 'delete'],
    account: ['create', 'read', 'update', 'delete'],
    report: ['read', 'export'],
  },
  hr: {
    employee: ['create', 'read', 'update', 'delete'],
    department: ['create', 'read', 'update', 'delete'],
    payroll: ['read', 'create', 'approve'],
    leave: ['create', 'read', 'approve'],
    attendance: ['read', 'create', 'update'],
  },
  crm: {
    contact: ['create', 'read', 'update', 'delete'],
    lead: ['create', 'read', 'update', 'delete', 'convert'],
    opportunity: ['create', 'read', 'update', 'delete'],
    activity: ['create', 'read', 'update', 'delete'],
  },
  inventory: {
    product: ['create', 'read', 'update', 'delete'],
    warehouse: ['create', 'read', 'update', 'delete'],
    stock: ['read', 'adjust', 'transfer'],
  },
  procurement: {
    vendor: ['create', 'read', 'update', 'delete'],
    'purchase-order': ['create', 'read', 'update', 'delete', 'approve'],
    rfq: ['create', 'read', 'update', 'delete'],
  },
  sales: {
    quotation: ['create', 'read', 'update', 'delete', 'send'],
    'sales-order': ['create', 'read', 'update', 'delete', 'confirm'],
    return: ['create', 'read', 'update', 'approve'],
  },
} as const;

/**
 * Default system roles with their permissions.
 */
export const DEFAULT_ROLES = {
  SUPER_ADMIN: {
    name: 'Super Admin',
    description: 'Full access to all features',
    permissions: ['*'],
    isSystem: true,
  },
  ADMIN: {
    name: 'Admin',
    description: 'Administrative access with user management',
    permissions: ['admin.*', 'finance.*', 'hr.*', 'crm.*', 'inventory.*'],
    isSystem: true,
  },
  FINANCE_MANAGER: {
    name: 'Finance Manager',
    description: 'Full access to finance module',
    permissions: ['finance.*', 'sales.sales-order.read'],
    isSystem: true,
  },
  HR_MANAGER: {
    name: 'HR Manager',
    description: 'Full access to HR module',
    permissions: ['hr.*'],
    isSystem: true,
  },
  SALES_REP: {
    name: 'Sales Representative',
    description: 'Access to CRM and sales features',
    permissions: [
      'crm.*',
      'sales.quotation.*',
      'sales.sales-order.create',
      'sales.sales-order.read',
      'inventory.product.read',
    ],
    isSystem: true,
  },
  VIEWER: {
    name: 'Viewer',
    description: 'Read-only access to all modules',
    permissions: [
      'finance.invoice.read',
      'finance.report.read',
      'hr.employee.read',
      'crm.contact.read',
      'inventory.product.read',
    ],
    isSystem: true,
  },
} as const;
