const mongoose = require('mongoose');

const adminLogSchema = new mongoose.Schema(
  {
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    admin_email: { type: String, default: '' },
    admin_role: { type: String, default: '' },
    action: { type: String, required: true },
    module: { type: String, default: '' }, // applications | deals | disputes | users | financials | shipping | settings | chat
    target_type: { type: String, default: '' }, // user | campaign | deal | dispute | withdrawal | setting
    target_id: { type: String, default: null },
    before: { type: mongoose.Schema.Types.Mixed, default: null },
    after: { type: mongoose.Schema.Types.Mixed, default: null },
    reason_code: { type: String, default: '' },
    reason_text: { type: String, default: '' },
    ip_address: { type: String, default: '' },
    user_agent: { type: String, default: '' },
    detail: { type: String, default: '' },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} }
  },
  {
    timestamps: true,
    // Immutable — no updates allowed
  }
);

// Prevent updates — audit logs are append-only
adminLogSchema.pre(['updateOne', 'findOneAndUpdate', 'updateMany'], function () {
  throw new Error('Audit logs are immutable');
});

module.exports = mongoose.model('AdminLog', adminLogSchema);
