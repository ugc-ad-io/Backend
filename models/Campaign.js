const mongoose = require('mongoose');

const campaignSchema = new mongoose.Schema({
  title: { type: String, required: true },
  business_id: { type: String, required: true }, // user ids may be UUID (migrated) or ObjectId — store as string
  business_nickname: { type: String, default: '' },
  status: { type: String, enum: ['draft', 'pending_approval', 'active', 'in_progress', 'work_submitted', 'completed', 'rejected'], default: 'pending_approval' },
  brief_text: { type: String, default: '' },
  objectives: { type: [String], default: [] },
  budget_min: { type: Number, default: 0 },
  budget_max: { type: Number, default: 0 },
  requires_shipment: { type: Boolean, default: false },
  bids: { type: Array, default: [] },
  selected_creator: { type: String, default: null },
  escrow_amount: { type: Number, default: 0 },
  category: { type: String, default: '' },
  deliverables: { type: String, default: '' },
  image_url: { type: String, default: '' }, // optional campaign banner/cover image
  work_submission: { type: mongoose.Schema.Types.Mixed, default: null },
  shipment: { type: mongoose.Schema.Types.Mixed, default: null },
  shortlist_invites: { type: [String], default: [] },
  due_date: { type: Date, default: null }
}, {
  timestamps: true,
  // The "Post a Brief" wizard sends ~50 structured fields (product_description,
  // campaign_hook, deliverable_items, usage_platforms, required_phrases, etc.).
  // strict:false persists all of them so a brief can be duplicated 1:1 — without
  // this, Mongoose silently drops every field not declared above.
  strict: false,
});

module.exports = mongoose.model('Campaign', campaignSchema);
