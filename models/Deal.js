const mongoose = require('mongoose');
const { DEAL_STATES, EXCEPTION_STATES } = require('../utils/dealStateMachine');

// --- Embedded sub-schemas ---------------------------------------------------

const briefSectionSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    content: { type: String, default: '' }
  },
  { _id: false }
);

const shipmentSchema = new mongoose.Schema(
  {
    tracking_id: { type: String, default: null },
    courier: { type: String, default: null },
    courier_status: { type: String, default: null },
    courier_tracking_url: { type: String, default: null },
    expected_delivery_at: { type: Date, default: null },
    shipped_at: { type: Date, default: null },
    delivered_at: { type: Date, default: null }
  },
  { _id: false }
);

const receiptSchema = new mongoose.Schema(
  {
    received_at: { type: Date, default: null },
    unboxing_video_url: { type: String, default: null },
    items_damaged: { type: Boolean, default: false },
    damage_report: { type: String, default: null }
  },
  { _id: false }
);

const contentVersionSchema = new mongoose.Schema(
  {
    version: { type: Number, required: true },
    video_url: { type: String, default: null },
    caption_url: { type: String, default: null },
    thumbnail_url: { type: String, default: null },
    raw_footage_url: { type: String, default: null },
    creator_note: { type: String, default: null },
    submitted_at: { type: Date, default: Date.now },
    // pending_review | approved | revision_requested
    status: { type: String, default: 'pending_review' }
  },
  { _id: false }
);

const contentSchema = new mongoose.Schema(
  {
    required_assets: {
      caption_script: { type: Boolean, default: false },
      thumbnail: { type: Boolean, default: false },
      raw_footage: { type: Boolean, default: false }
    },
    watermark_required_until_approval: { type: Boolean, default: true },
    // Set true while the watermark-removal job runs; surfaces the "Processing" state (6.10)
    watermark_removal_processing: { type: Boolean, default: false },
    versions: { type: [contentVersionSchema], default: [] }
  },
  { _id: false }
);

const revisionSchema = new mongoose.Schema(
  {
    revision_limit: { type: Number, default: 2 },
    revision_count_used: { type: Number, default: 0 },
    latest_feedback: { type: String, default: null },
    requested_changes: { type: [String], default: [] },
    new_deadline_at: { type: Date, default: null }
  },
  { _id: false }
);

const deductionSchema = new mongoose.Schema(
  {
    label: { type: String, required: true },
    amount: { type: Number, required: true }
  },
  { _id: false }
);

const escrowSchema = new mongoose.Schema(
  {
    held_amount: { type: Number, default: 0 },
    net_payable: { type: Number, default: 0 },
    deductions: { type: [deductionSchema], default: [] },
    estimated_payout_at: { type: Date, default: null },
    released_at: { type: Date, default: null },
    // held | queued | released | refunded
    status: { type: String, default: 'held' }
  },
  { _id: false }
);

const activityEventSchema = new mongoose.Schema(
  {
    actor_type: { type: String, default: 'system' }, // brand | creator | admin | system
    actor_name: { type: String, default: 'System' },
    event_type: { type: String, default: 'state_change' },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
  },
  { _id: true }
);

const chatMessageSchema = new mongoose.Schema(
  {
    sender_type: { type: String, default: 'system' }, // brand | creator | admin | system
    sender_name: { type: String, default: 'System' },
    message: { type: String, default: '' },
    attachment_urls: { type: [String], default: [] },
    created_at: { type: Date, default: Date.now }
  },
  { _id: true }
);

const actionCardSchema = new mongoose.Schema(
  {
    // milestone_update | damage_report | escalate_to_admin | raise_dispute | revision_request
    type: { type: String, required: true },
    title: { type: String, default: null },
    message: { type: String, default: '' },
    status: { type: String, default: 'open' }, // open | resolved
    attachment_urls: { type: [String], default: [] },
    created_by: { type: String, default: 'system' },
    created_at: { type: Date, default: Date.now }
  },
  { _id: true }
);

// --- Deal schema ------------------------------------------------------------

const dealSchema = new mongoose.Schema(
  {
    deal_id: { type: String, required: true, unique: true },

    campaign_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Gig', default: null },
    campaign_title: { type: String, default: 'Untitled campaign' },

    brand_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    brand_name: { type: String, default: 'Brand' },
    brand_handle: { type: String, default: 'brand' },
    brand_logo_url: { type: String, default: null },

    creator_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    creator_name: { type: String, default: 'Creator' },
    creator_handle: { type: String, default: 'creator' },

    current_state: {
      type: String,
      enum: [...DEAL_STATES, ...EXCEPTION_STATES],
      default: DEAL_STATES[0]
    },
    // Snapshot of the state we return to once an exception (dispute/damage) clears
    state_before_exception: { type: String, default: null },
    state_started_at: { type: Date, default: Date.now },
    next_deadline_at: { type: Date, default: null },

    bid_amount: { type: Number, default: 0 },

    brief_sections: { type: [briefSectionSchema], default: [] },
    shipment: { type: shipmentSchema, default: () => ({}) },
    receipt: { type: receiptSchema, default: () => ({}) },
    content: { type: contentSchema, default: () => ({}) },
    revision: { type: revisionSchema, default: () => ({}) },
    escrow: { type: escrowSchema, default: () => ({}) },

    approval: {
      approved_at: { type: Date, default: null },
      auto_approved: { type: Boolean, default: false }
    },

    dispute: {
      status: { type: String, default: null }, // open | resolved
      raised_by: { type: String, default: null },
      reason: { type: String, default: null },
      resolution: { type: String, default: null },
      resolved_at: { type: Date, default: null }
    },

    activity_feed: { type: [activityEventSchema], default: [] },
    messages: { type: [chatMessageSchema], default: [] },
    action_cards: { type: [actionCardSchema], default: [] },

    archived_by: { type: [mongoose.Schema.Types.ObjectId], default: [] }
  },
  { timestamps: true }
);

dealSchema.index({ brand_id: 1 });
dealSchema.index({ creator_id: 1 });
dealSchema.index({ current_state: 1 });

module.exports = mongoose.model('Deal', dealSchema);
