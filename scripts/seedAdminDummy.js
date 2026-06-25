/**
 * Seed dummy data for admin-side testing.
 *
 *   node scripts/seedAdminDummy.js
 *
 * Idempotent: every record it creates is tagged with the @demo.ugcad.io email
 * domain (users) or a DEMO- deal_id prefix, and those are wiped + re-created on
 * each run, so it never duplicates and never touches real data.
 *
 * Populates: Users (creators + brands, every state), Campaigns (every status),
 * Deals (every state incl. disputed/damaged, with escrow/shipment/content/chat).
 * That drives: Users, Analytics, Profiles, Campaigns, Deals, Disputes, Shipping,
 * Financials/Escrow and Assignments admin pages.
 */
require('dotenv').config();
const mongoose = require('mongoose');

const User = require('../models/User');
const Campaign = require('../models/Campaign');
const Deal = require('../models/Deal');

const { DEAL_STATES, EXCEPTION_STATES } = require('../utils/dealStateMachine');
const S = {
  AWAITING_SHIPMENT: DEAL_STATES[0],
  IN_TRANSIT: DEAL_STATES[1],
  AWAITING_RECEIPT: DEAL_STATES[2],
  IN_PROGRESS: DEAL_STATES[3],
  AWAITING_REVIEW: DEAL_STATES[4],
  REVISION: DEAL_STATES[5],
  PAYMENT_PROCESSING: DEAL_STATES[6],
  PAID: DEAL_STATES[7],
  DISPUTED: EXCEPTION_STATES[0],
  DAMAGED: EXCEPTION_STATES[1]
};

const DEMO_DOMAIN = '@demo.ugcad.io';
const daysFromNow = (n) => new Date(Date.now() + n * 86400000);
const hoursFromNow = (n) => new Date(Date.now() + n * 3600000);

async function run() {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Mongo connected');

  // ---- wipe previous demo data --------------------------------------------
  const oldUsers = await User.find({ email: { $regex: `${DEMO_DOMAIN}$` } }, '_id').lean();
  const oldIds = oldUsers.map((u) => u._id);
  await Deal.deleteMany({ deal_id: { $regex: '^DEMO-' } });
  await Campaign.deleteMany({ business_id: { $in: oldIds } });
  await User.deleteMany({ email: { $regex: `${DEMO_DOMAIN}$` } });
  console.log(`Cleared previous demo data (${oldIds.length} users)`);

  // ---- USERS ---------------------------------------------------------------
  // password is the same for all demo accounts so you can log in as any of them.
  const mk = (o) => ({ password: 'demo1234', profile_completed: true, ...o });

  const brandsData = [
    mk({ email: `glow.beauty${DEMO_DOMAIN}`, role: 'business', nickname: 'Glow Beauty', full_name: 'Glow Beauty Pvt Ltd', username: 'glowbeauty', approval_status: 'approved', wallet_balance: 84000, profile: { business_name: 'Glow Beauty', category: 'Beauty & Skincare', gstin: '27AABCG1234M1Z5', phone: '+91 98200 11111', website: 'glowbeauty.in' } }),
    mk({ email: `boltaudio${DEMO_DOMAIN}`, role: 'business', nickname: 'Bolt Audio', full_name: 'Bolt Audio Labs', username: 'boltaudio', approval_status: 'approved', wallet_balance: 152000, profile: { business_name: 'Bolt Audio', category: 'Electronics', gstin: '29AABCB5678N1Z2', phone: '+91 98200 22222', website: 'boltaudio.com' } }),
    mk({ email: `freshroots${DEMO_DOMAIN}`, role: 'business', nickname: 'Fresh Roots', full_name: 'Fresh Roots Nutrition', username: 'freshroots', approval_status: 'pending', submitted_at: hoursFromNow(-30), profile: { business_name: 'Fresh Roots', category: 'Health & Wellness', gstin: '06AABCF9012P1Z9', phone: '+91 98200 33333' } }),
    mk({ email: `urbanthread${DEMO_DOMAIN}`, role: 'business', nickname: 'Urban Thread', full_name: 'Urban Thread Apparel', username: 'urbanthread', approval_status: 'approved', wallet_balance: 12000, profile: { business_name: 'Urban Thread', category: 'Fashion', gstin: '07AABCU3456Q1Z1', phone: '+91 98200 44444' } })
  ];

  const creatorsData = [
    mk({ email: `swiftfox${DEMO_DOMAIN}`, role: 'creator', nickname: 'SwiftFox', full_name: 'Aanya Kapoor', username: 'SwiftFox757', public_creator_id: 'CR1042', approval_status: 'approved', wallet_balance: 4200, level: 2, payout_schedule: 'weekly', profile: { full_name: 'Aanya Kapoor', category: 'Beauty', phone: '+91 99300 11111', city: 'Mumbai', bank_account: '50100234567890', ifsc: 'HDFC0001234', upi: 'aanya@okhdfc' }, portfolio: [{ title: 'Skincare GRWM', url: 'https://example.com/v1' }] }),
    mk({ email: `pixelpriya${DEMO_DOMAIN}`, role: 'creator', nickname: 'Pixel Priya', full_name: 'Priya Nair', username: 'pixelpriya', public_creator_id: 'CR1088', approval_status: 'approved', wallet_balance: 15600, level: 3, payout_schedule: 'biweekly', profile: { full_name: 'Priya Nair', category: 'Tech', phone: '+91 99300 22222', city: 'Bengaluru', bank_account: '00112233445566', ifsc: 'ICIC0000456', upi: 'priya@okicici' } }),
    mk({ email: `reelrahul${DEMO_DOMAIN}`, role: 'creator', nickname: 'Reel Rahul', full_name: 'Rahul Mehta', username: 'reelrahul', approval_status: 'pending', submitted_at: hoursFromNow(-50), profile: { full_name: 'Rahul Mehta', category: 'Food', phone: '+91 99300 33333', city: 'Delhi' } }),
    mk({ email: `bannedbella${DEMO_DOMAIN}`, role: 'creator', nickname: 'Bella', full_name: 'Bella Dsouza', username: 'bellad', approval_status: 'approved', banned: true, ban_reason: 'Repeated off-platform solicitation', active: false, profile: { full_name: 'Bella Dsouza', category: 'Lifestyle', phone: '+91 99300 44444' } }),
    mk({
      email: `flaggedfreya${DEMO_DOMAIN}`, role: 'creator', nickname: 'Freya', full_name: 'Freya Sharma', username: 'freyas', approval_status: 'approved', wallet_balance: 2100,
      profile: { full_name: 'Freya Sharma', category: 'Fashion', phone: '+91 99300 55555', city: 'Pune' },
      chat: { strikes: [
        { at: hoursFromNow(-72), category: 'contact_info', matched: ['phone number'], snippet: 'you can reach me at 98xxxxxxxx' },
        { at: hoursFromNow(-20), category: 'evasion', matched: ['whatsapp'], snippet: 'lets move this to wa' }
      ] }
    }),
    mk({ email: `vlogvikram${DEMO_DOMAIN}`, role: 'creator', nickname: 'Vlog Vikram', full_name: 'Vikram Rao', username: 'vlogvikram', approval_status: 'approved', wallet_balance: 9800, level: 2, profile: { full_name: 'Vikram Rao', category: 'Travel', phone: '+91 99300 66666', city: 'Goa', upi: 'vikram@okaxis' } })
  ];

  const brands = [];
  for (const b of brandsData) brands.push(await User.create(b));
  const creators = [];
  for (const c of creatorsData) creators.push(await User.create(c));
  console.log(`Created ${brands.length} brands + ${creators.length} creators`);

  // ---- CAMPAIGNS -----------------------------------------------------------
  const campData = [
    { title: 'Summer Glow Skincare UGC', business_id: brands[0]._id, business_nickname: brands[0].nickname, status: 'active', category: 'beauty', brief_text: 'Authentic GRWM featuring our SPF serum. 30-45s vertical video.', budget_min: 4000, budget_max: 9000, requires_shipment: true, escrow_amount: 9000, deliverables: '1 reel + 3 photos', bids: [{ creator: 'SwiftFox757' }, { creator: 'freyas' }] },
    { title: 'Bolt Buds Pro Launch', business_id: brands[1]._id, business_nickname: brands[1].nickname, status: 'in_progress', category: 'electronics', brief_text: 'Unboxing + sound test of Bolt Buds Pro.', budget_min: 8000, budget_max: 18000, requires_shipment: true, escrow_amount: 15000, deliverables: '1 unboxing video', bids: [{ creator: 'pixelpriya' }] },
    { title: 'Fresh Roots Protein Review', business_id: brands[2]._id, business_nickname: brands[2].nickname, status: 'pending_approval', category: 'health', brief_text: 'Honest review of our plant protein.', budget_min: 3000, budget_max: 6000, requires_shipment: true, escrow_amount: 0, deliverables: '1 review reel' },
    { title: 'Urban Thread Winter Haul', business_id: brands[3]._id, business_nickname: brands[3].nickname, status: 'completed', category: 'fashion', brief_text: 'Try-on haul of the winter collection.', budget_min: 6000, budget_max: 12000, requires_shipment: true, escrow_amount: 12000, deliverables: '1 haul video' },
    { title: 'Glow Lip Tint Teaser', business_id: brands[0]._id, business_nickname: brands[0].nickname, status: 'rejected', category: 'beauty', brief_text: 'Quick teaser for new lip tints.', budget_min: 2000, budget_max: 4000, deliverables: '1 short' },
    { title: 'Bolt Speaker Outdoor Test', business_id: brands[1]._id, business_nickname: brands[1].nickname, status: 'active', category: 'electronics', brief_text: 'Outdoor durability + bass test.', budget_min: 7000, budget_max: 14000, requires_shipment: true, escrow_amount: 0, deliverables: '1 demo video', bids: [{ creator: 'vlogvikram' }] }
  ];
  const campaigns = [];
  for (const c of campData) campaigns.push(await Campaign.create(c));
  console.log(`Created ${campaigns.length} campaigns`);

  // ---- DEALS ---------------------------------------------------------------
  const briefSections = [
    { title: 'Deliverables', content: '1 vertical reel (30-45s) + 3 lifestyle photos' },
    { title: 'Talking points', content: 'Texture, SPF protection, no white cast' }
  ];
  const baseChat = (brand, creator) => ([
    { sender_type: 'brand', sender_name: brand.nickname, message: 'Hi! Excited to work with you on this.', created_at: hoursFromNow(-50) },
    { sender_type: 'creator', sender_name: creator.nickname, message: 'Likewise — when can you ship the product?', created_at: hoursFromNow(-48) },
    { sender_type: 'system', sender_name: 'System', message: 'Escrow funded by brand.', created_at: hoursFromNow(-47) }
  ]);
  const feed = (msgs) => msgs.map((m, i) => ({ actor_type: m[0], actor_name: m[1], event_type: m[2], message: m[3], timestamp: hoursFromNow(-60 + i * 6) }));

  const E = (held, status, days) => ({ held_amount: held, net_payable: Math.round(held * 0.8), deductions: [], status, estimated_payout_at: daysFromNow(days || 5) });

  let n = 0;
  const id = () => `DEMO-${String(++n).padStart(4, '0')}`;
  const dealFor = (campaign, brand, creator, state, extra = {}) => ({
    deal_id: id(),
    campaign_id: campaign._id,
    campaign_title: campaign.title,
    brand_id: brand._id, brand_name: brand.nickname, brand_handle: brand.username,
    creator_id: creator._id, creator_name: creator.nickname, creator_handle: creator.username,
    current_state: state,
    state_started_at: hoursFromNow(-12),
    bid_amount: campaign.budget_max,
    brief_sections: briefSections,
    escrow: E(campaign.budget_max, 'held'),
    messages: baseChat(brand, creator),
    activity_feed: feed([
      ['brand', brand.nickname, 'state_change', 'Deal created & escrow funded'],
      ['system', 'System', 'state_change', `Entered "${state}"`]
    ]),
    ...extra
  });

  const deals = [
    // 1 — awaiting shipment (brand to act), deadline soon
    dealFor(campaigns[0], brands[0], creators[0], S.AWAITING_SHIPMENT, { next_deadline_at: hoursFromNow(20) }),
    // 2 — in transit, with shipment
    dealFor(campaigns[1], brands[1], creators[1], S.IN_TRANSIT, {
      next_deadline_at: daysFromNow(3),
      shipment: { tracking_id: 'BLR789456123', courier: 'Delhivery', courier_status: 'In Transit', shipped_at: hoursFromNow(-30), ship_city: 'Bengaluru', ship_address: 'Indiranagar, Bengaluru 560038' }
    }),
    // 3 — content submitted, awaiting review (versions present)
    dealFor(campaigns[3], brands[3], creators[5], S.AWAITING_REVIEW, {
      next_deadline_at: hoursFromNow(8),
      shipment: { tracking_id: 'DEL112233', courier: 'BlueDart', courier_status: 'Delivered', shipped_at: hoursFromNow(-120), delivered_at: hoursFromNow(-90), ship_city: 'Goa' },
      receipt: { received_at: hoursFromNow(-80), items_damaged: false },
      content: { versions: [{ version: 1, video_url: 'https://example.com/demo-haul-v1.mp4', status: 'pending_review', submitted_at: hoursFromNow(-6) }] }
    }),
    // 4 — revision requested
    dealFor(campaigns[5], brands[1], creators[5], S.REVISION, {
      next_deadline_at: hoursFromNow(-4), // SLA breached
      content: { versions: [{ version: 1, video_url: 'https://example.com/demo-speaker-v1.mp4', status: 'revision_requested', submitted_at: hoursFromNow(-40) }] },
      revision: { revision_limit: 2, revision_count_used: 1, latest_feedback: 'Please add the bass test clip at the end.' }
    }),
    // 5 — paid / complete (escrow released)
    dealFor(campaigns[3], brands[3], creators[1], S.PAID, {
      escrow: { ...E(12000, 'released', -2), released_at: hoursFromNow(-20) },
      content: { versions: [{ version: 2, video_url: 'https://example.com/demo-final.mp4', status: 'approved', submitted_at: hoursFromNow(-30) }] },
      approval: { approved_at: hoursFromNow(-22), auto_approved: false }
    }),
    // 6 — DISPUTED
    dealFor(campaigns[1], brands[1], creators[0], S.DISPUTED, {
      next_deadline_at: hoursFromNow(-10),
      state_before_exception: S.AWAITING_REVIEW,
      dispute: { status: 'open', raised_by: 'creator', reason: 'Brand requested changes outside the agreed brief.' },
      escrow: E(15000, 'held'),
      content: { versions: [{ version: 1, video_url: 'https://example.com/demo-buds-v1.mp4', status: 'pending_review', submitted_at: hoursFromNow(-26) }] },
      action_cards: [{ type: 'raise_dispute', title: 'Dispute raised', message: 'Scope disagreement', created_by: 'creator' }]
    }),
    // 7 — DAMAGED product reported
    dealFor(campaigns[0], brands[0], creators[4], S.DAMAGED, {
      state_before_exception: S.AWAITING_RECEIPT,
      shipment: { tracking_id: 'MUM556677', courier: 'Ekart', courier_status: 'Delivered', shipped_at: hoursFromNow(-140), delivered_at: hoursFromNow(-100), ship_city: 'Pune' },
      receipt: { received_at: hoursFromNow(-95), items_damaged: true, damage_report: 'Serum bottle leaked, packaging crushed.' },
      escrow: E(9000, 'held')
    }),
    // 8 — payment processing, overdue (SLA breach flag)
    dealFor(campaigns[5], brands[1], creators[5], S.PAYMENT_PROCESSING, {
      next_deadline_at: hoursFromNow(-2),
      escrow: E(14000, 'queued', 1),
      content: { versions: [{ version: 1, video_url: 'https://example.com/demo-outdoor.mp4', status: 'approved', submitted_at: hoursFromNow(-30) }] }
    })
  ];
  for (const d of deals) await Deal.create(d);
  console.log(`Created ${deals.length} deals across every state`);

  console.log('\nDone. Log in as any demo account with password "demo1234" (e.g. swiftfox@demo.ugcad.io).');
  await mongoose.disconnect();
  process.exit(0);
}

run().catch((e) => { console.error(e); process.exit(1); });
