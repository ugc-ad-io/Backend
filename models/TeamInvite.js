const mongoose = require('mongoose');

/**
 * A pending invitation for someone to join a brand's workspace as a team member.
 * Deleted once accepted (the person then exists as a User with team_of = owner)
 * or revoked. Only the SHA-256 hash of the token is stored — the raw token lives
 * only in the emailed link.
 */
const teamInviteSchema = new mongoose.Schema(
  {
    owner_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    email: { type: String, required: true, lowercase: true, trim: true },
    role: { type: String, enum: ['admin', 'member', 'viewer'], default: 'member' },
    token_hash: { type: String, required: true, index: true },
    invited_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    expires_at: { type: Date, required: true },
  },
  { timestamps: true }
);

// One live invite per email per workspace.
teamInviteSchema.index({ owner_id: 1, email: 1 }, { unique: true });

module.exports = mongoose.models.TeamInvite || mongoose.model('TeamInvite', teamInviteSchema);
