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

/**
 * Hashes a plaintext password using bcrypt.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 10);
}

/**
 * Compares a plaintext password against a bcrypt hash.
 */
export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Signs a JWT payload.
 */
export function signToken(
  payload: string | object | Buffer,
  expiresIn: jwt.SignOptions['expiresIn'] = '1d',
): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
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
