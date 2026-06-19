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
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['creator', 'business', 'admin'], default: 'creator' },

    nickname: { type: String, default: '' },
    full_name: { type: String, default: '' },
    profile_photo: { type: String, default: null },
    profile_completed: { type: Boolean, default: false },
    approval_status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'approved' },
    active: { type: Boolean, default: true }, // false => suspended/deactivated (10.9)

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
  return bcrypt.compare(candidate, this.password);
};

// Public projection safe to return to the other party / client
userSchema.methods.toPublic = function () {
  return {
    id: this._id,
    user_id: this._id,
    email: this.email,
    role: this.role,
    nickname: this.nickname || this.full_name || this.email?.split('@')[0],
    full_name: this.full_name,
    profile_photo: this.profile_photo,
    profile_completed: this.profile_completed,
    approval_status: this.approval_status,
    active: this.active
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
