const mongoose = require('mongoose');

const ACTION_CARD_TYPES = [
  'custom_offer',
  'private_invitation',
  'counter_offer',
  'revision_request',
  'milestone_update',
  'damage_report',
  'escalate_to_admin',
  'raise_dispute'
];

/**
 * A single item in a thread. `item_type` distinguishes free-form messages,
 * structured Action Cards (immutable after send, 10.3/10.5), and system pills.
 */
const messageSchema = new mongoose.Schema(
  {
    thread_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Thread', required: true, index: true },

    item_type: { type: String, enum: ['message', 'action_card', 'system'], default: 'message' },

    sender_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    sender_type: { type: String, default: 'user' }, // user | admin | system
    recipient_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

    // free-form
    message: { type: String, default: '' },
    attachment_urls: { type: [String], default: [] },
    system_message: { type: Boolean, default: false },

    // read receipts
    status: { type: String, default: 'sent' }, // sent | delivered | read
    read_at: { type: Date, default: null },
    read_by: { type: [mongoose.Schema.Types.ObjectId], default: [] },

    // action card
    type: { type: String, enum: [...ACTION_CARD_TYPES, null], default: null },
    fields: { type: mongoose.Schema.Types.Mixed, default: {} },
    deal_id: { type: String, default: null },
    card_status: { type: String, default: 'open' }, // open | accepted | rejected | countered | partial | expired
    expires_at: { type: Date, default: null },
    counter_round: { type: Number, default: 0 },
    response: {
      action: { type: String, default: null },
      decline_reason: { type: String, default: null },
      note: { type: String, default: null },
      responded_at: { type: Date, default: null }
    }
  },
  { timestamps: true }
);

messageSchema.statics.ACTION_CARD_TYPES = ACTION_CARD_TYPES;

module.exports = mongoose.model('Message', messageSchema);
