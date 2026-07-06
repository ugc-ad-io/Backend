const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { MIN_CHAT_BALANCE } = require('../utils/chatPolicy');

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
    admin_role: { type: String, enum: ['founder', 'ops_senior', 'ops_regular', 'finance', null], default: null },
    // Work distribution — categories this admin handles (Ops Regular sees only
    // applications in these). Empty = no category queue. Founder/Senior see all.
    assigned_categories: { type: [String], default: [] },

    nickname: { type: String, default: '' },
    full_name: { type: String, default: '' },
    profile_photo: { type: String, default: null },
    banner: { type: String, default: null },
    profile_completed: { type: Boolean, default: false },
    approval_status: { type: String, enum: ['pending', 'more_info', 'approved', 'rejected'], default: 'approved' },
    // Admin review trail: { reason_code, reason_details, more_info_message, more_info_items[], requested_at, decided_at }
    review: { type: mongoose.Schema.Types.Mixed, default: {} },
    submitted_at: { type: Date, default: null }, // when onboarding was submitted (for SLA / oldest-first)
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
    profile: this.profile || {},
    portfolio: this.portfolio || [],
    review: this.review || {},
    submitted_at: this.submitted_at,
    created_at: this.createdAt
  };
};

// Self projection (adds wallet + settings + chat policy snapshot)
userSchema.methods.toSelf = function () {
  return {
    ...this.toPublic(),
    wallet_balance: this.wallet_balance,
    chat_unlocked: this.role !== 'business' || this.wallet_balance >= MIN_CHAT_BALANCE,
    settings: this.settings
  };
};

module.exports = mongoose.model('User', userSchema);
