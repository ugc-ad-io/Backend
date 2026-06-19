const mongoose = require('mongoose');

// Audit trail for admin chat actions (10.8) and user reports (10.9).
const adminLogSchema = new mongoose.Schema(
  {
    admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    action: { type: String, required: true }, // join_thread | post_message | pause_user | downgrade_user | export_transcript | report_user
    target_user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    target_thread_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Thread', default: null },
    detail: { type: String, default: '' },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} }
  },
  { timestamps: true }
);

module.exports = mongoose.model('AdminLog', adminLogSchema);
