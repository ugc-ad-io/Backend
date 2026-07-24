"""
Admin capability model (PRD 11 — Role structure). Python mirror of the Node
utils/adminRoles.js so both backends enforce the SAME matrix.

Roles:
  founder      → all operations, no restrictions ('*')
  ops_senior   → most ops + warn/suspend, wallet adjust, ₹1L disputes
  ops_regular  → review apps, disputes ≤ ₹25K, shipping, standard payouts
  finance      → view financials, reports, export tax docs
  custom       → founder-picked capabilities (user.admin_caps) + a data scope
                 (all / creators-only / brands-only)
"""

ADMIN_ROLES = ["founder", "ops_senior", "ops_regular", "finance", "custom"]

ROLE_LABELS = {
    "founder": "Founder / Admin",
    "ops_senior": "Ops (Senior)",
    "ops_regular": "Operations Team",
    "finance": "Finance",
    "custom": "Custom Admin",
}

# Every grantable capability (the custom-admin toggle list).
ALL_CAPS = [
    "review_applications", "my_users", "manage_deals", "rule_disputes", "manage_shipping",
    "release_payouts", "adjust_wallet", "warn_suspend_users", "ban_users",
    "view_financials", "generate_reports", "export_tax", "user_management",
    "content_moderation", "view_audit", "manage_roles",
    # Manage platform settings: payout ranges, payment/notification gateways.
    "edit_settings",
]

# Per-role dispute resolution ceiling (₹). None = no limit.
DISPUTE_CAP = {
    "founder": None,
    "ops_senior": 100000,
    "ops_regular": 25000,
    "finance": 0,
    "custom": 25000,
}

# Capability matrix. founder is a wildcard ('*'). custom uses the per-user
# admin_caps list instead of this table.
CAPS = {
    "founder": ["*"],
    "ops_senior": [
        "review_applications", "my_users", "manage_deals", "rule_disputes", "manage_shipping",
        "release_payouts", "adjust_wallet", "warn_suspend_users", "view_financials",
        "generate_reports", "user_management", "content_moderation", "view_audit",
    ],
    "ops_regular": [
        "review_applications", "my_users", "manage_deals", "rule_disputes", "manage_shipping",
        "release_payouts", "generate_reports", "content_moderation", "view_audit",
    ],
    "finance": [
        "view_financials", "generate_reports", "export_tax", "view_audit",
        # Finance owns payout ranges + payment/notification gateway config.
        "edit_settings",
    ],
    "custom": [],  # resolved from the user's own admin_caps
}


def normalize_role(role):
    """Admins with no explicit sub-role are treated as founder (legacy installs)."""
    return role if role in ADMIN_ROLES else "founder"


def can(user_or_role, capability, access="view") -> bool:
    """True if the admin has `capability`. Accepts a user dict
    ({admin_role, admin_caps, admin_cap_modes}) or a bare role string.

    Custom-admin capability modes are "view", "edit", or "both". Existing
    records without a mode map remain "both" for backward compatibility.
    """
    is_obj = isinstance(user_or_role, dict)
    role = normalize_role(user_or_role.get("admin_role") if is_obj else user_or_role)
    if role == "custom":
        caps = (user_or_role.get("admin_caps") or []) if is_obj else []
        if capability not in caps:
            return False
        mode = (user_or_role.get("admin_cap_modes") or {}).get(capability, "both")
        return mode == "both" or mode == access
    caps = CAPS.get(role, [])
    return "*" in caps or capability in caps


def dispute_cap(user_or_role):
    is_obj = isinstance(user_or_role, dict)
    role = normalize_role(user_or_role.get("admin_role") if is_obj else user_or_role)
    return DISPUTE_CAP.get(role, 0)


def scope_of(user) -> str:
    """Data scope for a custom admin: 'all' | 'creator' | 'business'."""
    if user and user.get("admin_role") == "custom":
        return user.get("admin_scope") or "all"
    return "all"


def user_scope_filter(user) -> dict:
    """Mongo filter fragment limiting the users collection to the admin's scope."""
    s = scope_of(user)
    return {} if s == "all" else {"role": s}


def in_scope(user, target_role) -> bool:
    """Whether an admin may act on a target with marketplace role `target_role`."""
    s = scope_of(user)
    if s == "all":
        return True
    if target_role not in ("creator", "business"):
        return True
    return target_role == s
