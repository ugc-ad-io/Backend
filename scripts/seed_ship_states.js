// Seed a spread of shipment states across a brand's deals so BOTH the brand's
// Manage Shipment view and the admin Shipping queue have rows to test with.
//   run:  node scripts/seed_ship_states.js testbrand@test.com
//   run:  node scripts/seed_ship_states.js b@gmail.com
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Deal = require('../models/Deal');

const BRAND_EMAIL = process.argv[2] || 'testbrand@test.com';
const AWAITING = 'Accepted - Awaiting Shipment';
const IN_TRANSIT = 'Shipped - In Transit';

const PICKUP = 'Test Brand Warehouse · +91 90000 00001\n12 Industrial Area, Andheri East, Mumbai, Maharashtra 400069';
const SHIPTO = 'Test Creator · +91 90000 00002\n45 MG Road, Indore, Madhya Pradesh 452001';

// The lifecycle stages we want represented in the queue.
const STAGES = [
  { key: 'requested', state: AWAITING, patch: () => ({ requested_at: new Date(), courier_status: 'requested', label_url: null, tracking_id: null, courier: null, shipped_at: null, delivered_at: null }) },
  { key: 'shipped',   state: IN_TRANSIT, patch: (i) => ({ requested_at: new Date(Date.now() - 864e5), courier_status: 'shipped', label_url: `/mock-labels/dummy-${i}.pdf`, tracking_id: `DUMMY${1000 + i}`, courier: 'Shiprocket (mock)', shipped_at: new Date() }) },
  { key: 'delivered', state: IN_TRANSIT, patch: (i) => ({ requested_at: new Date(Date.now() - 2 * 864e5), courier_status: 'delivered', label_url: `/mock-labels/dummy-${i}.pdf`, tracking_id: `DUMMY${2000 + i}`, courier: 'Shiprocket (mock)', shipped_at: new Date(Date.now() - 864e5), delivered_at: new Date() }) },
];

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  const brand = await User.findOne({ email: BRAND_EMAIL }).lean();
  if (!brand) { console.error(`No user with email ${BRAND_EMAIL}`); process.exit(1); }
  const deals = await Deal.find({ $or: [{ brand_id: brand._id }, { brand_id: String(brand._id) }] });
  if (!deals.length) { console.error(`No deals for ${BRAND_EMAIL}. Accept a creator on a shipment campaign first.`); process.exit(1); }
  console.log(`brand ${BRAND_EMAIL} → ${deals.length} deal(s); seeding ${Math.min(deals.length, STAGES.length)} stage(s)\n`);

  for (let i = 0; i < deals.length && i < STAGES.length; i++) {
    const deal = deals[i];
    const stage = STAGES[i];
    const base = deal.shipment && deal.shipment.toObject ? deal.shipment.toObject() : (deal.shipment || {});
    deal.shipment = {
      ...base,
      required: true,
      product_summary: `Dummy ${stage.key} item #${i + 1}`,
      weight: '0.6 kg',
      dimensions: '20×15×10 cm',
      pickup_address: PICKUP,
      ship_address: SHIPTO,
      ship_city: 'Indore',
      ...stage.patch(i + 1),
    };
    if (stage.key === 'delivered' && deal.receipt !== undefined) {
      deal.receipt = { ...(deal.receipt || {}), received_at: new Date() };
      deal.markModified('receipt');
    }
    deal.current_state = stage.state;
    deal.state_started_at = new Date();
    deal.markModified('shipment');
    await deal.save();
    console.log(`  ✅ ${stage.key.padEnd(10)} → deal ${deal.deal_id} · "${deal.campaign_title}" (${deal.current_state})`);
  }

  console.log('\nDone. Brand: Manage Shipment. Admin: Admin → Shipping.');
  await mongoose.disconnect();
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
