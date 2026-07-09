// One-off: seed a dummy shipment REQUEST on a deal owned by testbrand@gmail.com,
// so the admin-generates-label flow can be tested end to end.
//   run:  node scripts/seed_ship_dummy.js
require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const Deal = require('../models/Deal');
const Campaign = require('../models/Campaign');

const BRAND_EMAIL = 'testbrand@test.com';

(async () => {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('connected');

  const brand = await User.findOne({ email: BRAND_EMAIL }).lean();
  if (!brand) { console.error(`No user with email ${BRAND_EMAIL}`); process.exit(1); }
  console.log(`brand: ${brand._id} (${brand.nickname || brand.username || ''})`);

  const brandIdStr = String(brand._id);
  // Deals for this brand (brand_id may be stored as ObjectId or string).
  let deals = await Deal.find({ $or: [{ brand_id: brand._id }, { brand_id: brandIdStr }] });
  console.log(`found ${deals.length} deal(s) for this brand`);

  // Prefer a deal that's awaiting shipment; else fall back to the first one.
  let deal = deals.find((d) => /awaiting shipment/i.test(d.current_state || '')) || deals[0];

  if (!deal) {
    // No deal yet — make sure the brand has at least one shipment campaign, then bail
    // with guidance (creating a full accepted deal needs a creator + escrow).
    const camps = await Campaign.find({ $or: [{ business_id: brand._id }, { business_id: brandIdStr }] }).lean();
    console.error(`No deals for this brand. Campaigns: ${camps.length}. ` +
      `Accept a creator on a shipment campaign first, then re-run.`);
    process.exit(1);
  }

  // Dummy creator delivery address (normally pulled from the creator's profile).
  deal.shipment = {
    ...(deal.shipment && deal.shipment.toObject ? deal.shipment.toObject() : (deal.shipment || {})),
    required: true,
    requested_at: new Date(),
    product_summary: 'Skincare gift box (dummy test item)',
    weight: '0.6 kg',
    dimensions: '20×15×10 cm',
    pickup_address: 'Test Brand Warehouse · +91 90000 00001\n12 Industrial Area, Andheri East, Mumbai, Maharashtra 400069',
    ship_address: 'Test Creator · +91 90000 00002\n45 MG Road, Indore, Madhya Pradesh 452001',
    ship_city: 'Indore',
    courier_status: 'requested',
    label_url: null,
    tracking_id: null,
    courier: null,
    shipped_at: null,
    delivered_at: null,
  };
  if (Array.isArray(deal.activity_feed)) {
    deal.activity_feed.push({
      actor_type: 'brand', actor_name: deal.brand_name || 'Brand',
      event_type: 'shipment_requested',
      message: '[dummy] Brand submitted product & pickup details. Awaiting label.',
      timestamp: new Date(),
    });
  }
  // Put the deal back into the awaiting-shipment state so it appears in the admin
  // shipping queue and the whole process can be walked through.
  deal.current_state = 'Accepted - Awaiting Shipment';
  deal.state_started_at = new Date();
  deal.markModified('shipment');
  await deal.save();

  console.log('\n✅ Seeded dummy shipment REQUEST on:');
  console.log(`   deal_id:   ${deal.deal_id}`);
  console.log(`   campaign:  ${deal.campaign_title}  (campaign_id: ${deal.campaign_id})`);
  console.log(`   state:     ${deal.current_state}`);
  console.log('\nNext: open Admin → Shipping, generate the label + mark shipped for this deal.');
  await mongoose.disconnect();
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
