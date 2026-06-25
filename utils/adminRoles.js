/**
 * Admin role structure (PRD 11 — Role structure).
 *
 *   founder      → Founder / Admin  : all operations, no restrictions
 *   ops_senior   → Ops (Senior)     : all Regular Ops + ₹1L disputes, warn/suspend, wallet adjust
 *   ops_regular  → Ops (Regular)    : review apps, disputes ≤ ₹25K, shipping, standard payouts
 *   finance      → Finance          : view financials, reports, export tax docs
 *
 * This is the single source of truth for capabilities. The backend gates
 * endpoints with `can()` / `disputeCap()`; the frontend mirrors the same
 * matrix in src/utils/adminRoles.js for sidebar + button gating.
 */

const ADMIN_ROLES = ['founder', 'ops_senior', 'ops_regular', 'finance'];

const ROLE_LABELS = {
  founder: 'Founder / Admin',
  ops_senior: 'Ops (Senior)',
  ops_regular: 'Ops (Regular)',
  finance: 'Finance'
};

// Per-role dispute resolution ceiling (₹). Infinity = no limit.
const DISPUTE_CAP = {
  founder: Infinity,
  ops_senior: 100000,
  ops_regular: 25000,
  finance: 0
};

// Capability matrix. founder is a wildcard ('*' = everything).
const CAPS = {
  founder: ['*'],
  ops_senior: [
    'review_applications', 'manage_deals', 'rule_disputes', 'manage_shipping',
    'release_payouts', 'adjust_wallet', 'warn_suspend_users', 'view_financials',
    'generate_reports', 'user_management', 'content_moderation', 'view_audit'
  ],
  ops_regular: [
    'review_applications', 'manage_deals', 'rule_disputes', 'manage_shipping',
    'release_payouts', 'generate_reports', 'content_moderation', 'view_audit'
  ],
  finance: [
    'view_financials', 'generate_reports', 'export_tax', 'view_audit'
  ]
};

// Admins with no explicit admin_role (e.g. the original seed account) are
// treated as founder so existing single-admin installs keep full access.
const normalizeRole = (role) => (ADMIN_ROLES.includes(role) ? role : 'founder');

const can = (role, capability) => {
  const caps = CAPS[normalizeRole(role)] || [];
  return caps.includes('*') || caps.includes(capability);
};

const disputeCap = (role) => DISPUTE_CAP[normalizeRole(role)] ?? 0;

module.exports = { ADMIN_ROLES, ROLE_LABELS, DISPUTE_CAP, CAPS, can, disputeCap, normalizeRole };
