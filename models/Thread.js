const mongoose = require('mongoose');

/**
 * A chat thread is scoped to a counterparty PAIR, not a deal (10.6). It persists
 * across multiple deals between the same brand and creator.
 */
const threadSchema = new mongoose.Schema(
  {
    // Sorted [a, b] pair key so a thread is unique per pair
    participants: {
      type: [mongoose.Schema.Types.ObjectId],
      ref: 'User',
      required: true,
      validate: [(v) => v.length === 2, 'A thread must have exactly two participants']
    },
    pair_key: { type: String, required: true, unique: true }, // `${minId}_${maxId}`

    initiated_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    last_message: {
      message: { type: String, default: '' },
      sender_id: { type: mongoose.Schema.Types.ObjectId, default: null },
      item_type: { type: String, default: 'message' },
      attachment_urls: { type: [String], default: [] },
      timestamp: { type: Date, default: null }
    },

    // unread counts keyed by userId string
    unread: { type: Map, of: Number, default: {} },

    // typing timestamps keyed by userId string (best-effort, short-lived)
    typing: { type: Map, of: Date, default: {} },

    archived_by: { type: [mongoose.Schema.Types.ObjectId], default: [] },

    admin_joined: { type: Boolean, default: false }
  },
  { timestamps: true }
);

threadSchema.statics.pairKey = function (a, b) {
  return [String(a), String(b)].sort().join('_');
};

module.exports = mongoose.model('Thread', threadSchema);
