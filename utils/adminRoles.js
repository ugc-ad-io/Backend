/**
 * Admin role structure (PRD 11 — Role structure).
 *
 *   founder      → Founder / Admin  : all operations, no restrictions
 *   ops_senior   → Ops (Senior)     : all Regular Ops + ₹1L disputes, warn/suspend, wallet adjust
 *   ops_regular  → Ops (Regular)    : review apps, disputes ≤ ₹25K, shipping, standard payouts
 *   finance      → Finance          : view financials, reports, export tax docs
 *   custom       → Custom Admin     : founder-picked capabilities + a data scope
 *                                     (all / creators-only / brands-only)
 *
 * This is the single source of truth for capabilities. The backend gates
 * endpoints with `can()` / `disputeCap()`; the frontend mirrors the same
 * matrix in src/utils/adminRoles.js for sidebar + button gating.
 */

const ADMIN_ROLES = ['founder', 'ops_senior', 'ops_regular', 'finance', 'custom'];

const ROLE_LABELS = {
  founder: 'Founder / Admin',
  ops_senior: 'Ops (Senior)',
  ops_regular: 'Operations Team',
  finance: 'Finance',
  custom: 'Custom Admin'
};

// Every capability that can be granted to a custom admin (the toggle list).
const ALL_CAPS = [
  'review_applications', 'my_users', 'manage_deals', 'rule_disputes', 'manage_shipping',
  'release_payouts', 'adjust_wallet', 'warn_suspend_users', 'ban_users',
  'view_financials', 'generate_reports', 'export_tax', 'user_management',
  'content_moderation', 'view_audit', 'manage_roles',
  // Manage platform settings: payout ranges, payment/notification gateways.
  'edit_settings'
];

// Per-role dispute resolution ceiling (₹). Infinity = no limit.
const DISPUTE_CAP = {
  founder: Infinity,
  ops_senior: 100000,
  ops_regular: 25000,
  finance: 0,
  custom: 25000
};

// Capability matrix. founder is a wildcard ('*' = everything). custom uses the
// per-user `admin_caps` list instead of this table.
const CAPS = {
  founder: ['*'],
  ops_senior: [
    'review_applications', 'my_users', 'manage_deals', 'rule_disputes', 'manage_shipping',
    'release_payouts', 'adjust_wallet', 'warn_suspend_users', 'view_financials',
    'generate_reports', 'user_management', 'content_moderation', 'view_audit'
  ],
  ops_regular: [
    'review_applications', 'my_users', 'manage_deals', 'rule_disputes', 'manage_shipping',
    'release_payouts', 'generate_reports', 'content_moderation', 'view_audit'
  ],
  finance: [
    'view_financials', 'generate_reports', 'export_tax', 'view_audit',
    // Finance owns payout ranges + payment/notification gateway config.
    'edit_settings'
  ],
  custom: [] // resolved from the user's own admin_caps
};

// Admins with no explicit admin_role (e.g. the original seed account) are
// treated as founder so existing single-admin installs keep full access.
const normalizeRole = (role) => (ADMIN_ROLES.includes(role) ? role : 'founder');

// Accepts either a role string OR a user-like object { admin_role, admin_caps }.
// For custom admins the granted capabilities live on the object.
const can = (roleOrUser, capability) => {
  const isObj = roleOrUser && typeof roleOrUser === 'object';
  const role = normalizeRole(isObj ? roleOrUser.admin_role : roleOrUser);
  if (role === 'custom') {
    const caps = isObj ? (roleOrUser.admin_caps || []) : [];
    return caps.includes(capability);
  }
  const caps = CAPS[role] || [];
  return caps.includes('*') || caps.includes(capability);
};

const disputeCap = (roleOrUser) => {
  const role = normalizeRole(roleOrUser && typeof roleOrUser === 'object' ? roleOrUser.admin_role : roleOrUser);
  return DISPUTE_CAP[role] ?? 0;
};

// Data scope for a custom admin: 'all' | 'creator' | 'business'.
const scopeOf = (user) => (user && user.admin_role === 'custom' ? (user.admin_scope || 'all') : 'all');

// A Mongo filter fragment limiting the User collection to the admin's scope.
// 'all' → {} (no restriction). creator/business → { role: <scope> }.
const userScopeFilter = (user) => {
  const s = scopeOf(user);
  return s === 'all' ? {} : { role: s };
};

// Whether an admin may act on a target whose marketplace role is `targetRole`
// ('creator' | 'business'). Non-marketplace roles are always allowed.
const inScope = (user, targetRole) => {
  const s = scopeOf(user);
  if (s === 'all') return true;
  if (targetRole !== 'creator' && targetRole !== 'business') return true;
  return targetRole === s;
};

module.exports = {
  ADMIN_ROLES, ROLE_LABELS, ALL_CAPS, DISPUTE_CAP, CAPS,
  can, disputeCap, normalizeRole, scopeOf, userScopeFilter, inScope
};
