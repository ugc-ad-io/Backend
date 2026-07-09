// Create BRAND-NEW campaign+deal pairs (not touching existing data) with dummy
// shipment data across states, so the brand's Manage Shipment view and the admin
// Shipping queue both show fresh test rows.
//   run:  node scripts/seed_ship_new.js
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Deal = require('../models/Deal');
const Campaign = require('../models/Campaign');

const BRAND_EMAIL = 'testbrand@test.com';
const CREATOR_EMAIL = 'testcreator@test.com';

const AWAITING = 'Accepted - Awaiting Shipment';
const IN_TRANSIT = 'Shipped - In Transit';
const PICKUP = 'Test Brand Warehouse · +91 90000 00001\n12 Industrial Area, Andheri East, Mumbai, Maharashtra 400069';
const SHIPTO = 'Test Creator · +91 90000 00002\n45 MG Road, Indore, Madhya Pradesh 452001';

const STAGES = [
  { key: 'requested', title: '[TEST] Ship Request Demo', state: AWAITING,
    ship: () => ({ courier_status: 'requested', requested_at: new Date() }) },
  { key: 'shipped', title: '[TEST] Shipped Demo', state: IN_TRANSIT,
    ship: (i) => ({ courier_status: 'shipped', requested_at: new Date(Date.now() - 864e5), label_url: `/mock-labels/new-${i}.pdf`, tracking_id: `NEW${1000 + i}`, courier: 'Shiprocket (mock)', shipped_at: new Date() }) },
  { key: 'delivered', title: '[TEST] Delivered Demo', state: IN_TRANSIT,
    ship: (i) => ({ courier_status: 'delivered', requested_at: new Date(Date.now() - 2 * 864e5), label_url: `/mock-labels/new-${i}.pdf`, tracking_id: `NEW${2000 + i}`, courier: 'Shiprocket (mock)', shipped_at: new Date(Date.now() - 864e5), delivered_at: new Date() }) },
];

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  const brand = await User.findOne({ email: BRAND_EMAIL }).lean();
  const creator = await User.findOne({ email: CREATOR_EMAIL }).lean();
  if (!brand) { console.error(`No brand ${BRAND_EMAIL}`); process.exit(1); }
  if (!creator) { console.error(`No creator ${CREATOR_EMAIL}`); process.exit(1); }

  const brandName = brand.nickname || brand.username || 'Test Brand';
  const creatorName = creator.username ? `@${creator.username}` : (creator.nickname || 'Creator');
  const stamp = Date.now();

  for (let i = 0; i < STAGES.length; i++) {
    const st = STAGES[i];

    const campaign = await Campaign.create({
      title: st.title,
      business_id: String(brand._id),
      business_nickname: brandName,
      status: 'in_progress',
      requires_shipment: true,
      selected_creator: String(creator._id),
      budget_min: 5000, budget_max: 5000, escrow_amount: 5000,
      brief_text: 'Dummy brief for shipment testing.',
      deliverables: '1 UGC video',
      category: 'Beauty',
    });

    const shipment = {
      required: true,
      product_summary: `Dummy ${st.key} item`,
      weight: '0.6 kg',
      dimensions: '20×15×10 cm',
      pickup_address: PICKUP,
      ship_address: SHIPTO,
      ship_city: 'Indore',
      label_url: null, tracking_id: null, courier: null, shipped_at: null, delivered_at: null,
      ...st.ship(i + 1),
    };

    const deal = await Deal.create({
      deal_id: `TEST-${stamp}-${i}`,
      campaign_id: campaign._id,
      campaign_title: campaign.title,
      brand_id: brand._id,
      brand_name: brandName,
      brand_handle: brand.username || brandName,
      creator_id: creator._id,
      creator_name: creatorName,
      creator_handle: creator.username || creatorName,
      current_state: st.state,
      state_started_at: new Date(),
      next_deadline_at: new Date(Date.now() + 72 * 3600 * 1000),
      bid_amount: 5000,
      brief_sections: [
        { title: 'Deliverable', content: '1 UGC video' },
        { title: 'Brief', content: 'Dummy brief for shipment testing.' },
      ],
      shipment,
      receipt: st.key === 'delivered' ? { received_at: new Date() } : {},
      escrow: { held_amount: 5000, net_payable: 4000, status: 'held' },
      activity_feed: [{ actor_type: 'system', actor_name: 'System', event_type: 'accepted', message: `Dummy deal created (${st.key}).`, timestamp: new Date() }],
    });

    console.log(`  ✅ ${st.key.padEnd(10)} → deal ${deal.deal_id} · campaign "${campaign.title}" (${st.state})`);
  }

  console.log('\nDone. New test deals created for', BRAND_EMAIL, '↔', CREATOR_EMAIL);
  await mongoose.disconnect();
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
