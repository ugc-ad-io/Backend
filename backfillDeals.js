// One-time backfill: create Deal records for campaigns that were assigned a
// creator before deals were auto-created on selection. Safe to run repeatedly.
require('dotenv').config();
const mongoose = require('mongoose');
const Campaign = require('./models/Campaign');
const User = require('./models/User');
const Deal = require('./models/Deal');
const sm = require('./utils/dealStateMachine');

(async () => {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  const campaigns = await Campaign.find({
    selected_creator: { $ne: null },
    status: { $in: ['in_progress', 'work_submitted', 'completed'] }
  }).lean();

  const isObjectId = (v) => typeof v === 'string' && /^[a-fA-F0-9]{24}$/.test(v);

  let created = 0, skipped = 0, legacy = 0;
  for (const c of campaigns) {
    if (!c.selected_creator) { continue; }
    // Skip orphaned legacy rows that use UUID ids (no matching user records).
    if (!isObjectId(String(c.selected_creator)) || !isObjectId(String(c.business_id))) { legacy++; continue; }

    const existing = await Deal.findOne({ campaign_id: c._id, creator_id: c.selected_creator });
    if (existing) { skipped++; continue; }

    const creator = await User.findById(c.selected_creator).lean();
    const brand = await User.findById(c.business_id).lean();
    if (!creator || !brand) { legacy++; continue; }
    const bid = (c.bids || []).find((b) => String(b.creator_id) === String(c.selected_creator));
    const amount = (bid && bid.amount) || c.escrow_amount || c.budget_max || 0;
    const brandName = (brand && (brand.username ? `@${brand.username}` : brand.nickname)) || c.business_nickname || 'Brand';
    const creatorName = (creator && (creator.username ? `@${creator.username}` : creator.nickname)) || 'Creator';

    // Map current campaign status to a sensible deal state.
    let startState = c.requires_shipment ? sm.STATES.AWAITING_SHIPMENT : sm.STATES.IN_PROGRESS;
    if (c.status === 'work_submitted') startState = sm.STATES.AWAITING_REVIEW;
    if (c.status === 'completed') startState = sm.STATES.PAID;

    await Deal.create({
      deal_id: `UGC-${Date.now().toString().slice(-7)}-${created}`,
      campaign_id: c._id,
      campaign_title: c.title,
      brand_id: c.business_id,
      brand_name: brandName,
      brand_handle: (brand && brand.username) || brandName,
      creator_id: c.selected_creator,
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
      activity_feed: [{ actor_type: 'system', actor_name: 'System', event_type: 'accepted', message: `Deal backfilled for "${c.title}".`, timestamp: new Date() }]
    });
    created++;
    console.log(`  + Deal for campaign "${c.title}" -> creator ${c.selected_creator} (${startState})`);
  }

  console.log(`\nBackfill complete. Created ${created}, skipped ${skipped} (already had deals), legacy-skipped ${legacy} (UUID/orphaned).`);
  await mongoose.disconnect();
  process.exit(0);
})().catch((e) => { console.error('Backfill failed:', e); process.exit(1); });
