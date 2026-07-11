// Create (idempotently) the Deal that backs the Deal Room for a campaign+creator.
// Without it the campaign shows under "My Active Work" but the Deal Room is empty.
//
// Lives here rather than in server.js so the payment-fulfilment route can call the
// exact same code path — a deal born from a paid checkout must be identical to one
// born from a brand accepting a bid.
const User = require('../models/User');
const Deal = require('../models/Deal');
const sm = require('./dealStateMachine');

async function ensureDealForCampaign(c, creatorId, brandId) {
  const existing = await Deal.findOne({ campaign_id: c._id, creator_id: creatorId });
  if (existing) return existing;
  const creator = await User.findById(creatorId).lean();
  const brand = await User.findById(brandId).lean();
  const bid = (c.bids || []).find((b) => String(b.creator_id) === String(creatorId));
  // The escrowed amount is the creator's take (the subtotal). The platform fee is
  // charged to the brand on top and never enters escrow.
  const amount = (bid && bid.amount) || c.budget_max || c.budget_min || 0;
  const brandName = (brand && (brand.username ? `@${brand.username}` : brand.nickname)) || c.business_nickname || 'Brand';
  const creatorName = (creator && (creator.username ? `@${creator.username}` : creator.nickname)) || 'Creator';
  // No-shipment deals skip straight to content production.
  const startState = c.requires_shipment ? sm.STATES.AWAITING_SHIPMENT : sm.STATES.IN_PROGRESS;
  return Deal.create({
    deal_id: `UGC-${Date.now().toString().slice(-7)}`,
    campaign_id: c._id,
    campaign_title: c.title,
    brand_id: brandId,
    brand_name: brandName,
    brand_handle: (brand && brand.username) || brandName,
    creator_id: creatorId,
    creator_name: creatorName,
    creator_handle: (creator && creator.username) || creatorName,
    current_state: startState,
    state_started_at: new Date(),
    next_deadline_at: new Date(Date.now() + 72 * 3600 * 1000),
    bid_amount: amount,
    brief_sections: [
      { title: 'Deliverable', content: String(c.deliverables || 'As described in the brief') },
      { title: 'Brief', content: String(c.brief_text || 'As agreed') }
    ],
    shipment: { required: !!c.requires_shipment },
    escrow: { held_amount: amount, net_payable: amount, status: 'held' },
    activity_feed: [{ actor_type: 'system', actor_name: 'System', event_type: 'accepted', message: `Deal created — ${creatorName} selected for "${c.title}".`, timestamp: new Date() }]
  });
}

module.exports = { ensureDealForCampaign };
