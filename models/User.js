const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { MIN_CHAT_BALANCE } = require('../utils/chatPolicy');

// Creator level ladder. The DB stores a NUMBER (1..5) because promote/demote is
// just +1/-1, but every UI works in tier keys ('new', 'verified', …). Promoting
// used to look broken because toPublic() never sent the level, and the client
// then tried to read the number as a key. Both projections now carry all three.
const LEVEL_KEYS = ['new', 'verified', 'l1', 'l2', 'elite'];
const LEVEL_LABELS = { new: 'New', verified: 'Verified', l1: 'L1', l2: 'L2', elite: 'Elite' };
const MAX_LEVEL = LEVEL_KEYS.length;
const levelKeyOf = (n) => LEVEL_KEYS[Math.min(MAX_LEVEL, Math.max(1, Number(n) || 1)) - 1];

const strikeSchema = new mongoose.Schema(
  {
    at: { type: Date, default: Date.now },
    category: { type: String, default: 'contact_info' }, // contact_info | image | evasion
    thread_id: { type: mongoose.Schema.Types.ObjectId, default: null },
    matched: { type: [String], default: [] },
    snippet: { type: String, default: null },
    false_positive: { type: Boolean, default: false }
  },
  { _id: true }
);

const userSchema = new mongoose.Schema(
  {
    // The Python backend (which runs in production) looks users up by `id`, NOT `_id`.
    // Mongoose only writes `_id`, so any account created through this Node service was
    // born without an `id` and blew up Python with KeyError: 'id' (e.g. forgot-password
    // 500'd, so the reset email was never sent). Persisted by the pre-save hook below as
    // str(_id) — the same convention scripts/backfill_ids.py uses.
    id: { type: String, index: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    // Password is required for local (email/password) accounts only. Google
    // accounts authenticate via `google_id` and never have a password.
    password: { type: String, select: false, required: function () { return !this.google_id; } },
    // Google Sign-In: the account's Google subject id ('sub' claim). Set when a
    // user signs in with Google; used to link/find the account by Google identity.
    google_id: { type: String, default: null },
    auth_provider: { type: String, enum: ['local', 'google'], default: 'local' },
    // Password reset — a short-lived 6-digit code (stored as its SHA-256 hash,
    // never in the clear) is issued by /auth/forgot-password and consumed by
    // /auth/reset-password. Both hidden from normal reads via select:false.
    reset_code: { type: String, select: false, default: null },
    reset_code_expires: { type: Date, select: false, default: null },
    role: { type: String, enum: ['creator', 'business', 'admin'], default: 'creator' },
    // Admin sub-role / RBAC tier (PRD 11 — Role structure). Only meaningful when
    // role === 'admin'. null on legacy admins is treated as 'founder' (see toSelf).
    admin_role: { type: String, enum: ['founder', 'ops_senior', 'ops_regular', 'finance', 'custom', null], default: null },
    // Work distribution — categories this admin handles (Ops Regular sees only
    // applications in these). Empty = no category queue. Founder/Senior see all.
    assigned_categories: { type: [String], default: [] },
    // Custom admin role: the exact capabilities this admin has (used only when
    // admin_role === 'custom'), plus a data scope that limits which side of the
    // marketplace they can see/act on. 'all' = both creators and brands.
    admin_caps: { type: [String], default: [] },
    admin_scope: { type: String, enum: ['all', 'creator', 'business'], default: 'all' },

    nickname: { type: String, default: '' },
    full_name: { type: String, default: '' },
    profile_photo: { type: String, default: null },
    banner: { type: String, default: null },
    profile_completed: { type: Boolean, default: false },
    approval_status: { type: String, enum: ['pending', 'more_info', 'approved', 'rejected'], default: 'approved' },
    // Admin review trail: { reason_code, reason_details, more_info_message, more_info_items[], requested_at, decided_at }
    review: { type: mongoose.Schema.Types.Mixed, default: {} },
    submitted_at: { type: Date, default: null }, // when onboarding was submitted (for SLA / oldest-first)
    // "Complete your profile" nudge — set once the 24h auto-reminder (or an admin's
    // manual send) has fired, so the daily cron doesn't email the same user twice.
    // Cleared implicitly: once profile_completed flips true this field is just ignored.
    form_reminder_sent_at: { type: Date, default: null },
    active: { type: Boolean, default: true }, // false => suspended/deactivated (10.9)

    // Admin moderation state (spec 11.10 — Users module actions)
    banned: { type: Boolean, default: false },
    ban_reason: { type: String, default: '' },
    suspended_until: { type: Date, default: null },
    suspension_reason: { type: String, default: '' },
    warnings: {
      type: [new mongoose.Schema({
        message: { type: String, default: '' },
        at: { type: Date, default: Date.now },
        by: { type: String, default: '' }
      }, { _id: false })],
      default: []
    },
    level: { type: Number, default: 1 }, // V0.5: every creator is level 1 ('New')
    is_pro: { type: Boolean, default: false }, // brand Pro upgrade (V2)
    commission_rate: { type: Number, default: null }, // null => use platform default
    payout_schedule: { type: String, default: 'weekly' }, // weekly | biweekly | monthly | on_request

    // Onboarding handle + the FULL profile submitted on the signup form.
    // Mixed so every field the form sends (creator: bio, tags, languages,
    // social_links, rate_card, intro video, …; business: business_name,
    // website, gstin, logo, industry, …) is persisted verbatim and shown in
    // admin review.
    username: { type: String, default: null },
    public_creator_id: { type: String, default: null },
    profile: { type: mongoose.Schema.Types.Mixed, default: {} },
    portfolio: { type: mongoose.Schema.Types.Mixed, default: [] },
    reviews: { type: [mongoose.Schema.Types.Mixed], default: [] },
    average_rating: { type: Number, default: 0 },
    total_reviews: { type: Number, default: 0 },

    // Brand wallet — gate for chat initiation (10.2)
    wallet_balance: { type: Number, default: 0 },

    // Brand team / shared workspace. A brand owner can invite coworkers who log
    // in with their OWN credentials but see the OWNER's campaigns, deals and
    // wallet. `team_of` points at the owner (null = owner / not a team member);
    // `team_role` gates what they can do. Every brand-scoped query resolves
    // through workspaceId(req) = req.user.team_of || req.user.id.
    team_of: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    team_role: { type: String, enum: ['owner', 'admin', 'member', 'viewer'], default: 'owner' },
    team_seat_limit: { type: Number, default: 10 }, // only meaningful on the owner

    // Creator KYC (Aadhaar + PAN). A creator cannot withdraw earnings until an
    // admin has marked this `verified` — we are paying real money to a real
    // person, so the identity behind the payout account has to be checked.
    // Numbers are stored in full (an admin has to be able to match them to the
    // uploaded document) but never leave the server for anyone but the owner and
    // admins — toPublic()/toRedacted() do not include `kyc`.
    kyc: {
      // not_submitted -> pending -> verified | rejected  (rejected can resubmit)
      status: { type: String, enum: ['not_submitted', 'pending', 'verified', 'rejected'], default: 'not_submitted' },
      name_on_pan: { type: String, default: '' },
      pan_number: { type: String, default: '' },
      pan_doc_url: { type: String, default: '' },
      aadhaar_number: { type: String, default: '' },
      aadhaar_front_url: { type: String, default: '' },
      aadhaar_back_url: { type: String, default: '' },
      submitted_at: { type: Date, default: null },
      reviewed_at: { type: Date, default: null },
      reviewed_by: { type: String, default: '' },
      rejection_reason: { type: String, default: '' },
    },

    // Chat policy state (10.4)
    chat: {
      strikes: { type: [strikeSchema], default: [] },
      chat_paused_until: { type: Date, default: null },
      action_cards_only_until: { type: Date, default: null },
      suspended: { type: Boolean, default: false }
    },

    settings: {
      read_receipts: { type: Boolean, default: true },
      notifications: {
        email: { type: Boolean, default: true },
        sms: { type: Boolean, default: true },
        whatsapp: { type: Boolean, default: true }
      },
      timezone: { type: String, default: 'Asia/Kolkata' }
    }
  },
  { timestamps: true }
);

// Keep `id` in lockstep with `_id` so Python (which queries by `id`) can find the user.
userSchema.pre('save', function (next) {
  if (!this.id) this.id = this._id.toString();
  next();
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = function (candidate) {
  if (!this.password) return Promise.resolve(false); // Google-only account — no local password
  return bcrypt.compare(candidate, this.password);
};

// Public projection safe to return to the other party / client
userSchema.methods.toPublic = function () {
  return {
    id: this._id,
    user_id: this._id,
    email: this.email,
    role: this.role,
    // Admins always resolve to a concrete sub-role; legacy admins default to founder.
    admin_role: this.role === 'admin' ? (this.admin_role || 'founder') : null,
    admin_caps: this.admin_caps || [],
    admin_scope: this.admin_scope || 'all',
    nickname: this.nickname || this.full_name || this.email?.split('@')[0],
    full_name: this.full_name,
    profile_photo: this.profile_photo,
    banner: this.banner,
    profile_completed: this.profile_completed,
    approval_status: this.approval_status,
    active: this.active,
    admin_role: this.admin_role,
    assigned_categories: this.assigned_categories || [],
    username: this.username,
    public_creator_id: this.public_creator_id,
    // Creator level — number for the ladder, key + label for the UI.
    level: this.level || 1,
    level_key: levelKeyOf(this.level),
    level_label: LEVEL_LABELS[levelKeyOf(this.level)],
    profile: this.profile || {},
    portfolio: this.portfolio || [],
    review: this.review || {},
    submitted_at: this.submitted_at,
    created_at: this.createdAt
  };
};

// Show only the last N characters of an identity number ("XXXXXXXX4321").
const maskTail = (v, keep = 4) => {
  const s = String(v || '');
  if (!s) return '';
  return s.length <= keep ? s : `${'X'.repeat(s.length - keep)}${s.slice(-keep)}`;
};

// Keys inside the free-form `profile` blob that are PRIVATE to the user (and to
// admins). `profile` is stored verbatim from the onboarding form, so toPublic()
// spreading it wholesale would hand a creator's contact details — and their
// bank/UPI info, which /profile/payment-info writes to profile.payment_info —
// to any logged-in brand. Strip them for everyone else.
const PRIVATE_PROFILE_KEYS = [
  'payment_info', 'bank', 'bank_details', 'account_number', 'ifsc', 'upi', 'upi_id',
  'phone', 'phone_number', 'mobile', 'whatsapp', 'dialCode', 'dial_code',
  'address', 'pincode', 'pin_code', 'postal_code',
  'email', 'full_name', 'fullName',
  'aadhaar', 'aadhar', 'pan', 'gstin', 'id_proof',
  'date_of_birth', 'dob',
];

// Projection for a viewer who is neither the user nor an admin — e.g. a brand
// looking at a creator. Same shape as toPublic(), minus contact + payment PII.
userSchema.methods.toRedacted = function () {
  const pub = this.toPublic();
  const profile = { ...(pub.profile || {}) };
  PRIVATE_PROFILE_KEYS.forEach((k) => delete profile[k]);
  delete pub.email;
  delete pub.full_name;
  return { ...pub, profile };
};

// Self projection (adds wallet + settings + chat policy snapshot).
// KYC lives here and NOT in toPublic()/toRedacted() — a brand looking at a
// creator must never receive their Aadhaar/PAN. The number is masked even for
// the owner (the UI only ever needs to confirm which document is on file).
userSchema.methods.toSelf = function () {
  const k = this.kyc || {};
  return {
    ...this.toPublic(),
    wallet_balance: this.wallet_balance,
    chat_unlocked: this.role !== 'business' || this.wallet_balance >= MIN_CHAT_BALANCE,
    settings: this.settings,
    // Team context: the client hides brand-owner-only actions (e.g. managing the
    // team) from members, and read-only from viewers.
    team_of: this.team_of || null,
    team_role: this.team_role || 'owner',
    is_team_member: !!this.team_of,
    kyc: {
      status: k.status || 'not_submitted',
      name_on_pan: k.name_on_pan || '',
      pan_number: maskTail(k.pan_number, 4),
      aadhaar_number: maskTail(k.aadhaar_number, 4),
      submitted_at: k.submitted_at || null,
      reviewed_at: k.reviewed_at || null,
      rejection_reason: k.rejection_reason || '',
    },
  };
};

const User = mongoose.model('User', userSchema);

User.LEVEL_KEYS = LEVEL_KEYS;
User.LEVEL_LABELS = LEVEL_LABELS;
User.MAX_LEVEL = MAX_LEVEL;
User.levelKeyOf = levelKeyOf;

module.exports = User;
