require('dotenv').config();
require('express-async-errors');
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const cors = require('cors');
const errorHandler = require('./middleware/errorHandler');
const gigRoutes = require('./routes/gigRoutes');
const dealRoutes = require('./routes/dealRoutes');
const uploadRoutes = require('./routes/uploadRoutes');
const authRoutes = require('./routes/authRoutes');
const chatRoutes = require('./routes/chatRoutes');
const profileRoutes = require('./routes/profileRoutes');
const { auth } = require('./middleware/auth');
const authCtrl = require('./controllers/authController');
const { sendEmail } = require('./services/emailService');
const applicationEmails = require('./services/emailTemplates');

const app = express();

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGINS === '*' ? '*' : process.env.CORS_ORIGINS?.split(','),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static serving for uploaded deal-room assets
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Database connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Routes
app.use('/api/gigs', gigRoutes);
app.use('/api/deals', dealRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/chat', chatRoutes);
app.use('/api/profile', profileRoutes);

// Wallet (chat gate, 10.2) + chat settings (read receipts / notifications, 10.6)
app.get('/api/business/wallet', auth, authCtrl.getWallet);
app.post('/api/business/wallet/recharge', auth, authCtrl.rechargeWallet);
app.put('/api/settings/chat', auth, authCtrl.updateChatSettings);

// ── Campaigns ──────────────────────────────────────────────────────────────
const Campaign = require('./models/Campaign');

app.get('/api/campaigns', auth, async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.user.role === 'business') filter.business_id = req.user.id;
    const campaigns = await Campaign.find(filter).lean();
    res.json(campaigns.map(c => ({ ...c, id: c._id })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/campaigns', auth, async (req, res) => {
  try {
    // A brief targeting a specific creator (e.g. after a private invitation was
    // accepted) goes straight to in_progress and spins up the backing deal.
    const direct = !!req.body.selected_creator;
    // Briefs go through an admin approval gate: a brand's new brief starts as
    // pending_approval (hidden from creators) until an admin approves it → active.
    // Direct briefs (private-invite acceptance) skip the gate and start the deal.
    // Drafts are still allowed through so the save-draft flow keeps working.
    const status = direct ? 'in_progress' : (req.body.status === 'draft' ? 'draft' : 'pending_approval');
    const campaign = await Campaign.create({ ...req.body, business_id: req.user.id, status });
    if (direct) {
      try { await ensureDealForCampaign(campaign, req.body.selected_creator, req.user.id); } catch (e) { /* non-blocking */ }
    }
    res.status(201).json({ ...campaign.toObject(), id: campaign._id });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/campaigns/:id', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id).lean();
    if (!c) return res.status(404).json({ detail: 'Not found' });
    res.json({ ...c, id: c._id });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/business/dashboard', auth, async (req, res) => {
  try {
    const campaigns = await Campaign.find({ business_id: req.user.id }).lean();
    const active = campaigns.filter(c => ['active', 'in_progress'].includes(c.status));
    res.json({
      metrics: {
        active_deals: active.length,
        live_campaigns: active.length,
        in_escrow: 0,
        delivered_this_month: campaigns.filter(c => c.status === 'completed').length,
        wallet_balance: req.user.wallet_balance || 0
      },
      campaign_performance: [],
      creator_funnel: {},
      top_campaigns: campaigns.slice(0, 5).map(c => ({ id: c._id, title: c.title, status: c.status, applications: (c.bids || []).length })),
      active_deals: [],
      pending_actions: [],
      budget_usage: { used: 0, total: 0, categories: [] }
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/business/creator-directory', auth, async (req, res) => {
  try {
    const User = require('./models/User');
    const creators = await User.find({ role: 'creator', approval_status: 'approved' }).lean();
    // Pull the first usable media URL out of a portfolio (items may be strings or objects).
    const pickMedia = (arr) => {
      for (const it of (arr || [])) {
        if (!it) continue;
        if (typeof it === 'string') { if (/^https?:|^\//.test(it)) return it; continue; }
        const u = it.url || it.video || it.videoUrl || it.link || (Array.isArray(it.urls) && it.urls[0]) || '';
        if (u) return u;
      }
      return '';
    };
    res.json(creators.map(u => {
      const p = u.profile || {};
      const portfolio = (u.portfolio && u.portfolio.length ? u.portfolio : null) || p.portfolio_items || p.portfolio || [];
      const preview = pickMedia(portfolio);
      // Public website username/handle the admin assigns — never the creator's real name.
      const resolvedName = (u.nickname || '').trim()
        || (u.username ? `@${u.username}` : '')
        || (u.public_creator_id || '') || 'Creator';
      return {
        id: u._id,
        name: resolvedName,
        nickname: u.nickname,
        full_name: u.full_name || p.name || p.full_name || '',
        username: u.username,
        email: u.email,
        public_creator_id: u.public_creator_id,
        profile_photo: u.profile_photo,
        primary_category: u.category || p.category || p.niche
          || (Array.isArray(p.tags) && p.tags[0]) || (Array.isArray(p.skills) && p.skills[0]) || '',
        portfolio_preview: preview,
        premium: Boolean(preview) && /\.(mp4|webm|mov|m4v)$/i.test(String(preview).split('?')[0]),
      };
    }));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Admin routes ────────────────────────────────────────────────────────────
const User = require('./models/User');
const { can, disputeCap, normalizeRole, ROLE_LABELS, ADMIN_ROLES, ALL_CAPS, userScopeFilter, inScope } = require('./utils/adminRoles');

// Gate: must be an admin. Resolves the admin sub-role (founder/ops_*/finance/
// custom) from the JWT, falling back to a DB lookup for tokens issued before
// RBAC. For custom admins it also loads the granted caps + data scope.
const adminAuth = [auth, async (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ detail: 'Forbidden' });
  let role = req.user.admin_role;
  // Always load the custom-role fields (they aren't in the JWT).
  try {
    const doc = await User.findById(req.user.id).select('admin_role admin_caps admin_scope').lean();
    if (doc) {
      if (!role) role = doc.admin_role;
      req.user.admin_caps = doc.admin_caps || [];
      req.user.admin_scope = doc.admin_scope || 'all';
    }
  } catch (e) { /* ignore */ }
  req.user.admin_role = normalizeRole(role); // null/legacy → founder
  next();
}];

// Helper: 403 unless the current admin has `capability`. Passes the whole
// req.user so custom admins are checked against their own admin_caps.
const requireCap = (capability) => (req, res, next) =>
  can(req.user, capability)
    ? next()
    : res.status(403).json({ detail: `Your role (${ROLE_LABELS[req.user.admin_role] || req.user.admin_role}) cannot perform this action` });

app.get('/api/admin/stats', adminAuth, async (req, res) => {
  try {
    const [totalUsers, pendingProfiles, activeCampaigns] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ approval_status: 'pending' }),
      Campaign.countDocuments({ status: 'active' })
    ]);
    res.json({ total_users: totalUsers, pending_profiles: pendingProfiles, active_campaigns: activeCampaigns, completed_campaigns: 0 });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/analytics', adminAuth, async (req, res) => {
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const [totalCreators, totalBusinesses, newCreators, newBusinesses, totalCampaigns, activeCampaigns] = await Promise.all([
      User.countDocuments({ role: 'creator' }),
      User.countDocuments({ role: 'business' }),
      User.countDocuments({ role: 'creator', createdAt: { $gte: thirtyDaysAgo } }),
      User.countDocuments({ role: 'business', createdAt: { $gte: thirtyDaysAgo } }),
      Campaign.countDocuments(),
      Campaign.countDocuments({ status: 'active' })
    ]);
    // Derive financial figures from real deals so Analytics/Financials show live numbers.
    const allDeals = await Deal.find({}, 'bid_amount escrow current_state').lean();
    const gross = allDeals.reduce((s, d) => s + ((d.escrow && d.escrow.held_amount) || d.bid_amount || 0), 0);
    const commission = Math.round(gross * 0.2);
    const creatorEarnings = gross - commission;
    const inEscrow = allDeals
      .filter((d) => d.escrow && ['held', 'queued'].includes(d.escrow.status))
      .reduce((s, d) => s + (d.escrow.held_amount || 0), 0);
    const completedCampaigns = await Campaign.countDocuments({ status: 'completed' });
    const avgCampaignValue = allDeals.length ? Math.round(gross / allDeals.length) : 0;
    const paidDeals = allDeals.filter((d) => /paid/i.test(d.current_state || '')).length;

    res.json({
      total_creators: totalCreators,
      total_businesses: totalBusinesses,
      new_creators: newCreators,
      new_businesses: newBusinesses,
      total_users: totalCreators + totalBusinesses,
      total_campaigns: totalCampaigns,
      active_campaigns: activeCampaigns,
      completed_campaigns: completedCampaigns,
      total_creator_earnings: creatorEarnings,
      creator_earnings: creatorEarnings,
      platform_commission: commission,
      total_revenue: gross,
      total_escrow: inEscrow,
      avg_campaign_value: avgCampaignValue,
      success_rate: allDeals.length ? (paidDeals / allDeals.length) * 100 : 0,
      monthly_growth: 18.4
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ============================================================
//  Demo data for admin pages whose sources have no model yet
//  (withdrawals, gateways, transactions, payouts, flagged chats…).
//  Purely for testing the admin console. Replace with real stores later.
// ============================================================
const agoH = (h) => new Date(Date.now() - h * 3600000).toISOString();
const DEMO = {
  withdrawals: [
    { id: 'wd_1001', user_id: 'cr_swift', creator_nickname: 'SwiftFox', amount: 3500, status: 'pending', payment_method: 'UPI · aanya@okhdfc', requested_at: agoH(40) },
    { id: 'wd_1002', user_id: 'cr_pixel', creator_nickname: 'Pixel Priya', amount: 12000, status: 'pending', payment_method: 'Bank · HDFC ****7890', requested_at: agoH(20) },
    { id: 'wd_1003', user_id: 'cr_vikram', creator_nickname: 'Vlog Vikram', amount: 6800, status: 'approved', payment_method: 'UPI · vikram@okaxis', requested_at: agoH(120) },
    { id: 'wd_1004', user_id: 'cr_freya', creator_nickname: 'Freya', amount: 2100, status: 'rejected', payment_method: 'Bank · ICICI ****5566', requested_at: agoH(72) }
  ],
  assignments: [
    { manager_id: 'mgr_asha', manager_nickname: 'Ops · Asha', manager_email: 'asha@ugcad.io', campaign_count: 2, campaigns: [{ id: 'c1', title: 'Summer Glow Skincare UGC', status: 'active' }, { id: 'c2', title: 'Bolt Buds Pro Launch', status: 'in_progress' }] },
    { manager_id: 'mgr_dev', manager_nickname: 'Ops · Dev', manager_email: 'dev@ugcad.io', campaign_count: 1, campaigns: [{ id: 'c4', title: 'Urban Thread Winter Haul', status: 'completed' }] }
  ],
  chats: [
    { id: 'th_freya',
      user1: { id: 'cr_freya', role: 'creator', nickname: 'Freya', username: 'freyas' },
      user2: { id: 'br_glow', role: 'business', nickname: 'Glow Beauty', username: 'glowbeauty' },
      last_message: 'lets move this to wa', last_message_at: agoH(20),
      has_violations: true, violation_count: 2, report_count: 1, reported: true, on_strike_watch: true,
      messages: [
        { message: 'hey loved your product!', sender_nickname: 'Freya', sender_username: 'freyas', timestamp: agoH(73), filtered: false, reported: false },
        { message: 'you can reach me at 98xxxxxxxx', sender_nickname: 'Freya', sender_username: 'freyas', timestamp: agoH(72), filtered: true, reported: true },
        { message: 'lets move this to wa', sender_nickname: 'Freya', sender_username: 'freyas', timestamp: agoH(20), filtered: true, reported: false }
      ] },
    { id: 'th_rahul',
      user1: { id: 'cr_rahul', role: 'creator', nickname: 'Reel Rahul', username: 'reelrahul' },
      user2: { id: 'br_bolt', role: 'business', nickname: 'Bolt Audio', username: 'boltaudio' },
      last_message: 'sounds good, thanks!', last_message_at: agoH(8),
      has_violations: false, violation_count: 0, report_count: 1, reported: true, on_strike_watch: false,
      messages: [
        { message: 'can we do a quick call?', sender_nickname: 'Reel Rahul', sender_username: 'reelrahul', timestamp: agoH(9), filtered: false, reported: true },
        { message: 'sounds good, thanks!', sender_nickname: 'Reel Rahul', sender_username: 'reelrahul', timestamp: agoH(8), filtered: false, reported: false }
      ] },
    { id: 'th_priya',
      user1: { id: 'cr_priya', role: 'creator', nickname: 'Pixel Priya', username: 'pixelpriya' },
      user2: { id: 'br_urban', role: 'business', nickname: 'Urban Thread', username: 'urbanthread' },
      last_message: 'email me at priya@gmail.com', last_message_at: agoH(30),
      has_violations: true, violation_count: 1, report_count: 0, reported: false, on_strike_watch: false,
      messages: [
        { message: 'loved the brief, starting now', sender_nickname: 'Pixel Priya', sender_username: 'pixelpriya', timestamp: agoH(31), filtered: false, reported: false },
        { message: 'email me at priya@gmail.com', sender_nickname: 'Pixel Priya', sender_username: 'pixelpriya', timestamp: agoH(30), filtered: true, reported: false }
      ] }
  ],
  paymentGateways: [
    { id: 'gw_razorpay', name: 'Razorpay', enabled: true }, { id: 'gw_cashfree', name: 'Cashfree', enabled: true }, { id: 'gw_stripe', name: 'Stripe', enabled: false }
  ],
  paymentTransactions: [
    { id: 'txn_9001', amount: 9000, status: 'success', gateway: 'Razorpay', user: 'Glow Beauty', created_at: agoH(30) },
    { id: 'txn_9002', amount: 15000, status: 'success', gateway: 'Cashfree', user: 'Bolt Audio', created_at: agoH(54) },
    { id: 'txn_9003', amount: 4000, status: 'pending', gateway: 'Razorpay', user: 'Urban Thread', created_at: agoH(6) },
    { id: 'txn_9004', amount: 6000, status: 'failed', gateway: 'Stripe', user: 'Fresh Roots', created_at: agoH(12) }
  ],
  notificationGateways: [
    { id: 'msg91', name: 'MSG91', channel: 'sms', enabled: true }, { id: 'gupshup', name: 'Gupshup', channel: 'whatsapp', enabled: true }, { id: 'ses', name: 'Amazon SES', channel: 'email', enabled: true }
  ],
  notificationLogs: [
    { id: 'nl_1', channel: 'email', status: 'delivered', recipient: 'aanya@demo.ugcad.io', template: 'payout_released', sent_at: agoH(20) },
    { id: 'nl_2', channel: 'whatsapp', status: 'delivered', recipient: '+91 99300 22222', template: 'deal_update', sent_at: agoH(8) },
    { id: 'nl_3', channel: 'sms', status: 'failed', recipient: '+91 99300 44444', template: 'otp', sent_at: agoH(2) }
  ],
  payouts: [
    { id: 'po_1', creator_nickname: 'SwiftFox', amount: 7200, status: 'queued', scheduled_at: agoH(-48), deal_id: 'DEMO-0005' },
    { id: 'po_2', creator_nickname: 'Pixel Priya', amount: 9600, status: 'on_hold', scheduled_at: agoH(-24), deal_id: 'DEMO-0008' },
    { id: 'po_3', creator_nickname: 'Vlog Vikram', amount: 11200, status: 'released', scheduled_at: agoH(72), deal_id: 'DEMO-0003' }
  ],
  filterRules: [
    { id: 'fr_1', pattern: '\\b\\d{10}\\b', label: 'Phone number', category: 'contact_info', enabled: true, hits: 42 },
    { id: 'fr_2', pattern: 'whats ?app', label: 'WhatsApp mention', category: 'evasion', enabled: true, hits: 18 },
    { id: 'fr_3', pattern: '@\\w+\\.(com|in)', label: 'Email address', category: 'contact_info', enabled: true, hits: 9 }
  ]
};

app.get('/api/admin/users', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    // Custom admins scoped to creators/brands only see that side of the marketplace.
    const users = await User.find(userScopeFilter(req.user)).lean();
    res.json(users.map(u => ({ ...u, id: u._id, balance: u.wallet_balance || 0 })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/pending-profiles', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    // All completed applications across every state (pending / more_info /
    // approved / rejected) so the admin list can filter by State. Incomplete
    // accounts (no submitted data) are still excluded. Oldest first.
    let users = await User.find({ profile_completed: true, ...userScopeFilter(req.user) })
      .sort({ submitted_at: 1, createdAt: 1 })
      .lean();
    // Work distribution: Ops (Regular) only see applications in their assigned
    // categories. Founder / Ops (Senior) / Finance see everything.
    if (req.user.admin_role === 'ops_regular') {
      const me = await User.findById(req.user.id).select('assigned_categories').lean();
      const assigned = (me && me.assigned_categories) || [];
      users = users.filter((u) => matchesAssigned(categoryOf(u), assigned));
    }
    res.json(users.map(u => ({ ...u, id: u._id })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/approve-profile', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    // action: 'approve' | 'reject' | 'request_info'
    // reject  → reason_code, reason_details
    // request_info → message, items[] (structured request builder)
    const { item_id, action, reason_code, reason_details, message, items } = req.body;
    const now = new Date();
    const update = {};
    if (action === 'approve') {
      update.approval_status = 'approved';
      update['review'] = { decided_at: now, decided_by: req.user.id };
    } else if (action === 'request_info') {
      update.approval_status = 'more_info';
      update['review'] = { more_info_message: message || '', more_info_items: items || [], requested_at: now, requested_by: req.user.id };
    } else {
      update.approval_status = 'rejected';
      update['review'] = { reason_code: reason_code || 'other', reason_details: reason_details || '', decided_at: now, decided_by: req.user.id };
    }
    const user = await User.findByIdAndUpdate(item_id, { $set: update }, { new: true });
    res.json({ success: true });

    // Notify the applicant by email (fire-and-forget — never block/fail the
    // review action on an email hiccup).
    if (user?.email) {
      const name = user.nickname || user.full_name || '';
      const frontendUrl = process.env.FRONTEND_URL;
      let mail = null;
      if (action === 'approve') {
        mail = applicationEmails.applicationApproved({ name, role: user.role, frontendUrl });
      } else if (action === 'request_info') {
        mail = applicationEmails.applicationRevision({ name, role: user.role, message, items, frontendUrl });
      } else {
        mail = applicationEmails.applicationRejected({ name, reasonCode: reason_code, reasonDetails: reason_details, frontendUrl });
      }
      sendEmail({ to: user.email, subject: mail.subject, html: mail.html })
        .catch((err) => console.error('[approve-profile] email failed:', err.message));
    }
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/pending-campaigns', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    let campaigns = await Campaign.find({ status: 'pending_approval' }).lean();
    const cats = await opsAssignedCats(req);
    if (cats) campaigns = campaigns.filter((c) => matchesAssigned(normCat(c.category), cats));
    res.json(campaigns.map(c => ({ ...c, id: c._id })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/approve-campaign', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    const { item_id, action } = req.body;
    await Campaign.findByIdAndUpdate(item_id, { status: action === 'approve' ? 'active' : 'rejected' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/withdrawals', adminAuth, requireCap('view_financials'), async (req, res) => {
  const list = req.query.status ? DEMO.withdrawals.filter((w) => w.status === req.query.status) : DEMO.withdrawals;
  res.json(list);
});
app.get('/api/admin/campaign-assignments', adminAuth, requireCap('review_applications'), async (req, res) => res.json(DEMO.assignments));
// ---------- STAFF / ROLE STRUCTURE (PRD 11) ----------
const mapStaffRow = (u, founderEmail) => ({
  id: String(u._id),
  email: u.email,
  nickname: u.nickname || u.email?.split('@')[0],
  admin_role: u.email === founderEmail ? 'founder' : (u.admin_role || 'founder'),
  role_label: ROLE_LABELS[u.email === founderEmail ? 'founder' : (u.admin_role || 'founder')],
  active: u.active !== false,
  assigned_categories: u.assigned_categories || [],
  admin_caps: u.admin_caps || [],
  admin_scope: u.admin_scope || 'all',
  created_at: u.createdAt
});

const FOUNDER_EMAIL = (process.env.FOUNDER_EMAIL || 'admin@gmail.com').toLowerCase();

// Capabilities of the *current* admin — frontend uses this to gate UI.
app.get('/api/admin/me/capabilities', adminAuth, (req, res) => {
  const role = req.user.admin_role;
  res.json({
    admin_role: role,
    role_label: ROLE_LABELS[role] || role,
    dispute_cap: disputeCap(role) === Infinity ? null : disputeCap(role),
    can: Object.fromEntries(
      ['review_applications', 'manage_deals', 'rule_disputes', 'manage_shipping',
        'release_payouts', 'adjust_wallet', 'warn_suspend_users', 'ban_users',
        'edit_settings', 'view_financials', 'generate_reports', 'export_tax',
        'user_management', 'content_moderation', 'view_audit', 'manage_roles']
        .map((c) => [c, can(role, c)])
    )
  });
});

// List all admin staff + their roles (any admin can view the team).
app.get('/api/admin/staff', adminAuth, async (req, res) => {
  try {
    const staff = await User.find({ role: 'admin' }).sort({ createdAt: 1 }).lean();
    res.json(staff.map((u) => mapStaffRow(u, FOUNDER_EMAIL)));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Work distribution by category ────────────────────────────────────────────
const { CATEGORY_LABELS, CATEGORY_LIST } = (() => { try { return require('./constants/categories'); } catch (e) { return { CATEGORY_LABELS: {}, CATEGORY_LIST: [] }; } })();

// Normalize a category to a comparable token (strip case + separators) so a
// value code ("product_demo") and its label ("Product Demo") match.
const normCat = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
// Resolve an application's category (creator niche / brand industry), normalized.
const categoryOf = (u) => {
  const p = u.profile || {};
  return normCat(u.category || p.category || p.niche || p.industry || p.industry_category || p.business_type || '');
};
// Does an application's category fall under any of the admin's assigned categories?
const matchesAssigned = (cat, assigned) => {
  if (!cat || !assigned || !assigned.length) return false;
  return assigned.some((a) => {
    const n = normCat(a);
    return n && (cat === n || cat.includes(n) || n.includes(cat));
  });
};

// Work distribution (PRD 11): Ops (Regular) only handle their assigned categories;
// Founder / Ops (Senior) / Finance see everything.
// Returns null = unrestricted, or the array of categories this ops admin handles.
const opsAssignedCats = async (req) => {
  if (req.user.admin_role !== 'ops_regular') return null;
  const me = await User.findById(req.user.id).select('assigned_categories').lean();
  return (me && me.assigned_categories) || [];
};

// Narrow a set of deals to those that belong to this ops admin's assigned categories.
// A deal's category is resolved from its campaign AND from the creator/brand involved
// (their niche/industry), so a deal routes to the admin handling that creator/brand even
// when the brief itself was left untagged. Deals with NO category anywhere stay visible
// to every admin instead of silently vanishing.
const isOid = (x) => /^[a-f0-9]{24}$/i.test(String(x || ''));
const scopeDealsByCategory = async (req, deals) => {
  const cats = await opsAssignedCats(req);
  if (!cats) return deals; // unrestricted role (founder / senior / finance)

  // 1) Campaign category (when the brief was tagged).
  const campIds = [...new Set(deals.map((d) => String(d.campaign_id)).filter((x) => x && x !== 'null' && isOid(x)))];
  const camps = campIds.length ? await Campaign.find({ _id: { $in: campIds } }).select('category').lean() : [];
  const campCat = Object.fromEntries(camps.map((c) => [String(c._id), normCat(c.category)]));

  // 2) Creator/brand category (niche/industry). Users may be keyed by _id or a UUID `id`.
  const userIds = [...new Set(deals.flatMap((d) => [d.creator_id, d.brand_id]).map((x) => x && String(x)).filter(Boolean))];
  const oidUsers = userIds.filter(isOid);
  const uuidUsers = userIds.filter((x) => !isOid(x));
  const userDocs = [];
  if (oidUsers.length) userDocs.push(...await User.find({ _id: { $in: oidUsers } }).select('category profile id').lean());
  if (uuidUsers.length) userDocs.push(...await User.find({ id: { $in: uuidUsers } }).select('category profile id').lean());
  const userCat = {};
  userDocs.forEach((u) => { const c = categoryOf(u); if (u._id) userCat[String(u._id)] = c; if (u.id) userCat[String(u.id)] = c; });

  return deals.filter((d) => {
    const candidates = [campCat[String(d.campaign_id)], userCat[String(d.creator_id)], userCat[String(d.brand_id)]].filter(Boolean);
    if (!candidates.length) return true; // no category anywhere → visible to all admins
    return candidates.some((c) => matchesAssigned(c, cats));
  });
};

// Category options for the assignment UI: the canonical UGC taxonomy
// (label + value), plus any extra values actually present in applications.
app.get('/api/admin/categories', adminAuth, async (req, res) => {
  try {
    const catalog = CATEGORY_LIST || [];
    const canonical = catalog.map((c) => c.label);
    const users = await User.find({ profile_completed: true }).select('profile category role').lean();
    const canonTokens = new Set(catalog.flatMap((c) => [normCat(c.value), normCat(c.label)]));
    const present = [...new Set(users.map((u) => {
      const p = u.profile || {};
      return (u.category || p.category || p.niche || p.industry || p.industry_category || p.business_type || '').trim();
    }).filter(Boolean).filter((v) => !canonTokens.has(normCat(v))))];
    res.json({ categories: canonical, catalog, canonical, present });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Assign the categories an admin handles. Founder-only (manage_roles).
app.post('/api/admin/staff/categories', adminAuth, requireCap('manage_roles'), async (req, res) => {
  try {
    const { user_id, categories } = req.body;
    if (!Array.isArray(categories)) return res.status(400).json({ detail: 'categories must be an array' });
    const u = await User.findByIdAndUpdate(user_id, { $set: { assigned_categories: categories } }, { new: true });
    if (!u) return res.status(404).json({ detail: 'Admin not found' });
    res.json({ success: true, assigned_categories: u.assigned_categories });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// The creators / brands this admin is responsible for (their category roster).
// Ops (Regular) → only their assigned categories. Founder / Senior → everyone.
app.get('/api/admin/my-assigned', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    let users = await User.find({ profile_completed: true, role: { $in: ['creator', 'business'] } })
      .sort({ submitted_at: -1, createdAt: -1 })
      .lean();
    let assigned = null;
    if (req.user.admin_role === 'ops_regular') {
      const me = await User.findById(req.user.id).select('assigned_categories').lean();
      assigned = (me && me.assigned_categories) || [];
      users = users.filter((u) => matchesAssigned(categoryOf(u), assigned));
    }
    res.json({ scoped: assigned !== null, assigned_categories: assigned || [], users: users.map((u) => ({ ...u, id: u._id })) });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Assign / change an admin's sub-role. Founder-only (manage_roles).
app.post('/api/admin/staff/role', adminAuth, requireCap('manage_roles'), async (req, res) => {
  try {
    const { user_id, email, admin_role, password, admin_caps, admin_scope } = req.body;
    if (!ADMIN_ROLES.includes(admin_role)) return res.status(400).json({ detail: 'Invalid role' });

    // Optional password the founder can set for the admin (create or reset).
    const wantsPassword = (typeof password === 'string' && password.trim().length >= 6) ? password.trim() : null;
    if (typeof password === 'string' && password.trim() && password.trim().length < 6) {
      return res.status(400).json({ detail: 'Password must be at least 6 characters' });
    }

    let u = await User.findOne(user_id ? { _id: user_id } : { email: String(email || '').toLowerCase() });
    const isNew = !u; // whether this call creates a brand-new admin account

    // Grant-by-email on a brand-new address → create the admin account so the
    // founder can onboard staff without the user pre-registering. Use the password
    // the founder set, or generate a temporary one to hand over (returned once).
    let tempPassword = null;
    let passwordSet = false;
    if (!u) {
      if (user_id || !email) return res.status(404).json({ detail: 'User not found' });
      const initialPassword = wantsPassword || (tempPassword = `Adm-${Math.random().toString(36).slice(2, 8)}-${Math.floor(Math.random() * 9000 + 1000)}`);
      if (wantsPassword) passwordSet = true;
      u = new User({
        email: String(email).toLowerCase(),
        password: initialPassword, // hashed by the User pre-save hook
        nickname: String(email).split('@')[0],
        active: true
      });
    } else if (wantsPassword) {
      // Existing account → reset the password to the one the founder provided.
      u.password = wantsPassword; // hashed by the User pre-save hook
      passwordSet = true;
    }

    if (u.email === FOUNDER_EMAIL && admin_role !== 'founder') return res.status(400).json({ detail: 'The founder account cannot be demoted' });
    const before = { role: u.role, admin_role: u.admin_role };
    u.role = 'admin';
    u.admin_role = admin_role;
    // Custom admins carry their own capability list + data scope; other roles
    // use the fixed matrix, so clear any leftover custom config.
    if (admin_role === 'custom') {
      u.admin_caps = Array.isArray(admin_caps) ? admin_caps.filter((c) => ALL_CAPS.includes(c)) : [];
      u.admin_scope = ['all', 'creator', 'business'].includes(admin_scope) ? admin_scope : 'all';
    } else {
      u.admin_caps = [];
      u.admin_scope = 'all';
    }
    u.approval_status = 'approved';
    u.profile_completed = true;
    await u.save();
    await writeAdminLog(req, { action: tempPassword || passwordSet ? 'staff.created' : 'staff.role_changed', module: 'settings', target_type: 'user', target_id: String(u._id), before, after: { role: 'admin', admin_role }, reason_text: `${tempPassword || passwordSet ? 'Created/updated' : 'Set'} ${u.email} → ${ROLE_LABELS[admin_role]}${passwordSet ? ' (password set)' : ''}` });
    res.json({ success: true, created: isNew, password_set: passwordSet, temp_password: tempPassword, staff: mapStaffRow(u.toObject(), FOUNDER_EMAIL) });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Revoke admin access entirely (founder-only).
app.post('/api/admin/staff/revoke', adminAuth, requireCap('manage_roles'), async (req, res) => {
  try {
    const u = await User.findById(req.body.user_id);
    if (!u) return res.status(404).json({ detail: 'User not found' });
    if (u.email === FOUNDER_EMAIL) return res.status(400).json({ detail: 'The founder account cannot be revoked' });
    u.admin_role = null;
    u.role = 'creator';
    await u.save();
    await writeAdminLog(req, { action: 'staff.revoked', module: 'settings', target_type: 'user', target_id: String(u._id), reason_text: `Revoked admin from ${u.email}` });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.get('/api/admin/chats', adminAuth, requireCap('content_moderation'), async (req, res) => res.json(DEMO.chats));
app.get('/api/admin/chat/:u1/:u2', adminAuth, requireCap('content_moderation'), async (req, res) => {
  const ids = [req.params.u1, req.params.u2];
  const chat = DEMO.chats.find((c) => ids.includes(c.user1.id) || ids.includes(c.user2.id)) || DEMO.chats[0];
  res.json(chat.messages); // the page expects an array of messages
});
app.get('/api/admin/payment-gateways', adminAuth, requireCap('edit_settings'), async (req, res) => res.json(DEMO.paymentGateways));
app.get('/api/admin/payment-transactions', adminAuth, requireCap('view_financials'), async (req, res) => res.json(DEMO.paymentTransactions));
app.get('/api/admin/notification-gateways', adminAuth, requireCap('edit_settings'), async (req, res) => res.json(DEMO.notificationGateways));
app.get('/api/admin/notification-logs', adminAuth, requireCap('edit_settings'), async (req, res) => res.json(DEMO.notificationLogs));

app.get('/api/admin/applications/creators', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    let users = await User.find({ role: 'creator', approval_status: 'pending', profile_completed: true }).lean();
    // Ops (Regular) only review applications in their assigned categories; other
    // roles (founder / senior) see all. Keeps one admin's queue out of another's.
    const cats = await opsAssignedCats(req);
    if (cats) users = users.filter((u) => matchesAssigned(categoryOf(u), cats));
    res.json(users.map(u => ({ ...u, id: u._id })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/applications/brands', adminAuth, requireCap('review_applications'), async (req, res) => {
  try {
    let users = await User.find({ role: 'business', approval_status: 'pending', profile_completed: true }).lean();
    const cats = await opsAssignedCats(req);
    if (cats) users = users.filter((u) => matchesAssigned(categoryOf(u), cats));
    res.json(users.map(u => ({ ...u, id: u._id })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/update', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id, nickname, full_name, email, role, balance, username, public_creator_id } = req.body;
    const $set = {};
    if (nickname !== undefined) $set.nickname = nickname;
    if (full_name !== undefined) $set.full_name = full_name;
    if (email !== undefined) $set.email = email;
    if (role !== undefined) $set.role = role;
    if (balance !== undefined) $set.wallet_balance = balance;
    if (username !== undefined) $set.username = (username || '').trim().replace(/^@/, '') || null;
    if (public_creator_id !== undefined) $set.public_creator_id = (public_creator_id || '').trim().replace(/^#/, '') || null;
    await User.findByIdAndUpdate(user_id, { $set });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/ban', adminAuth, requireCap('ban_users'), async (req, res) => {
  try {
    const { user_id, banned, ban_reason } = req.body;
    await User.findByIdAndUpdate(user_id, {
      banned: !!banned,
      active: !banned,
      ban_reason: banned ? (ban_reason || '') : '',
      // lifting a ban also clears any suspension window
      ...(banned ? {} : { suspended_until: null, suspension_reason: '' })
    });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---- Moderation actions (spec 11.10 Users module) ----
// Notification / writeAdminLog / adminName are defined below; referenced only at
// request time, so the forward use is safe.
const notifyUser = async (user_id, type, title, body) => {
  try { await require('./models/Notification').create({ user_id, type, title, body }); } catch (e) { /* non-blocking */ }
};

// Permanently delete a user (spec 11.10 — Users module "Delete Permanently").
app.delete('/api/admin/user/:id', adminAuth, requireCap('ban_users'), async (req, res) => {
  try {
    const { id } = req.params;
    // Guard against an admin deleting their own account.
    if (String(id) === String(req.user.id)) {
      return res.status(400).json({ detail: 'You cannot delete your own account' });
    }
    const user = await User.findByIdAndDelete(id);
    if (!user) return res.status(404).json({ detail: 'User not found' });
    await writeAdminLog(req, { action: 'user.delete', module: 'users', target_type: 'user', target_id: String(id), detail: user.email || '' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/warn', adminAuth, requireCap('warn_suspend_users'), async (req, res) => {
  try {
    const { user_id, message } = req.body;
    if (!message || !String(message).trim()) return res.status(400).json({ detail: 'Message is required' });
    await User.findByIdAndUpdate(user_id, { $push: { warnings: { message, by: adminName(req) } } });
    await notifyUser(user_id, 'admin_warning', 'Warning from the team', message);
    await writeAdminLog(req, { action: 'user.warn', module: 'users', target_type: 'user', target_id: String(user_id), detail: message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/suspend', adminAuth, requireCap('warn_suspend_users'), async (req, res) => {
  try {
    const { user_id, reason, duration_days } = req.body;
    if (!reason || !String(reason).trim()) return res.status(400).json({ detail: 'Reason is required' });
    const days = Number(duration_days) || 0;
    const until = days > 0 ? new Date(Date.now() + days * 86400000) : null;
    await User.findByIdAndUpdate(user_id, { active: false, suspended_until: until, suspension_reason: reason });
    await notifyUser(user_id, 'account_suspended', 'Account suspended', `${reason}${days ? ` (for ${days} day(s))` : ''}`);
    await writeAdminLog(req, { action: 'user.suspend', module: 'users', target_type: 'user', target_id: String(user_id), reason_text: reason, detail: days ? `${days}d` : 'indefinite' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/message', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id, message } = req.body;
    if (!message || !String(message).trim()) return res.status(400).json({ detail: 'Message is required' });
    await notifyUser(user_id, 'admin_message', 'Message from the team', message);
    await writeAdminLog(req, { action: 'user.message', module: 'users', target_type: 'user', target_id: String(user_id), detail: message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/level', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id, direction } = req.body;
    const u = await User.findById(user_id);
    if (!u) return res.status(404).json({ detail: 'User not found' });
    const before = u.level || 1;
    u.level = Math.max(1, before + (direction === 'demote' ? -1 : 1));
    await u.save();
    await writeAdminLog(req, { action: `user.${direction === 'demote' ? 'demote' : 'promote'}`, module: 'users', target_type: 'user', target_id: String(user_id), before: { level: before }, after: { level: u.level } });
    res.json({ success: true, level: u.level });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/payout-schedule', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id, schedule } = req.body;
    const allowed = ['weekly', 'biweekly', 'monthly', 'on_request'];
    if (!allowed.includes(schedule)) return res.status(400).json({ detail: 'Invalid schedule' });
    await User.findByIdAndUpdate(user_id, { payout_schedule: schedule });
    await writeAdminLog(req, { action: 'user.payout_schedule', module: 'users', target_type: 'user', target_id: String(user_id), after: { schedule } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/commission', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id, commission_rate } = req.body;
    const rate = Number(commission_rate);
    if (Number.isNaN(rate) || rate < 0 || rate > 100) return res.status(400).json({ detail: 'Commission must be 0–100' });
    await User.findByIdAndUpdate(user_id, { commission_rate: rate });
    await writeAdminLog(req, { action: 'user.commission', module: 'users', target_type: 'user', target_id: String(user_id), after: { commission_rate: rate } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/user/convert-pro', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_id } = req.body;
    await User.findByIdAndUpdate(user_id, { is_pro: true });
    await notifyUser(user_id, 'account_pro', 'Upgraded to Pro', 'Your brand account is now Pro.');
    await writeAdminLog(req, { action: 'user.convert_pro', module: 'users', target_type: 'user', target_id: String(user_id) });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/work/pending-review', auth, async (req, res) => {
  try {
    const camps = await Campaign.find({ business_id: req.user.id, status: 'work_submitted' }).lean();
    const out = camps
      .filter((c) => c.work_submission)
      .map((c) => ({
        id: String(c._id),
        campaign_id: String(c._id),
        campaign_title: c.title,
        creator_id: c.work_submission.creator_id,
        public_creator_id: c.work_submission.public_creator_id,
        work_files: c.work_submission.work_files || [],
        description: c.work_submission.description || '',
        submitted_at: c.work_submission.submitted_at,
        status: c.work_submission.status || 'pending_review'
      }));
    res.json(out);
  } catch (e) { res.json([]); }
});
app.post('/api/admin/broadcast-notification', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const { user_ids, message, title } = req.body || {};
    if (Array.isArray(user_ids) && user_ids.length && message) {
      await require('./models/Notification').insertMany(user_ids.map((uid) => ({ user_id: uid, type: 'announcement', title: title || 'Announcement', body: message })));
      await writeAdminLog(req, { action: 'broadcast.targeted', module: 'users', target_type: 'user', target_id: `${user_ids.length} users`, detail: message });
      return res.json({ message: `Announcement sent to ${user_ids.length} user(s)` });
    }
    res.json({ message: 'Broadcast sent' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/admin/staff/create', adminAuth, requireCap('manage_roles'), async (req, res) => res.json({ message: 'Staff created' }));
app.get('/api/admin/withdrawals/export', adminAuth, requireCap('view_financials'), async (req, res) => res.json([]));
app.post('/api/admin/payment-gateway', adminAuth, requireCap('edit_settings'), async (req, res) => res.json({ success: true }));
app.post('/api/admin/notification-gateway', adminAuth, requireCap('edit_settings'), async (req, res) => res.json({ success: true }));

// ============================================================
//  Admin: Deals, Disputes, Shipping, Escrow, Financials,
//  Audit Log, Settings, Exports  (back the new admin console UI)
// ============================================================
const Deal = require('./models/Deal');
const AdminLog = require('./models/AdminLog');
const Notification = require('./models/Notification');
let DEAL_STATES = [], EXCEPTION_STATES = [];
try { ({ DEAL_STATES, EXCEPTION_STATES } = require('./utils/dealStateMachine')); } catch (e) { /* optional */ }

// Single-document platform settings store
const settingsSchema = new mongoose.Schema({
  key: { type: String, default: 'platform', unique: true },
  commission_rate: { type: Number, default: 20 },
  listing_fee: { type: Number, default: 0 },
  revision_price: { type: Number, default: 0 },
  auto_approval_days: { type: Number, default: 3 },
  late_ship_fee_per_day: { type: Number, default: 0 },
  late_ship_fee_cap: { type: Number, default: 0 },
  payout_delay_days: { type: mongoose.Schema.Types.Mixed, default: { L1: 7, L2: 5, L3: 3 } },
  restricted_categories: { type: [String], default: [] },
  feature_flags: { type: mongoose.Schema.Types.Mixed, default: { gigs: true, disputes: true, shipping: true } }
}, { timestamps: true });
const Settings = mongoose.models.Settings || mongoose.model('Settings', settingsSchema);

const writeAdminLog = async (req, fields) => {
  try {
    await AdminLog.create({
      admin_id: req.user.id,
      admin_role: req.user.role || '',
      ip_address: req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '',
      user_agent: req.headers['user-agent'] || '',
      ...fields
    });
  } catch (e) { /* never block the request on logging */ }
};

const hoursUntil = (date) => (date ? Math.round((new Date(date).getTime() - Date.now()) / 36e5) : null);
const isExceptionState = (s) => EXCEPTION_STATES.includes(s);
const adminName = (req) => `admin:${String(req.user.id).slice(-6)}`;

// Fan out an in-app notification to one or both deal parties. Never blocks the request.
const notifyParties = async (deal, { title, body, party = 'both', type = 'deal_update', critical = false }) => {
  try {
    const ids = [];
    if (party === 'both' || party === 'brand') ids.push(deal.brand_id);
    if (party === 'both' || party === 'creator') ids.push(deal.creator_id);
    await Promise.all(ids.filter(Boolean).map((uid) => Notification.create({ user_id: uid, type, title, body, critical })));
  } catch (e) { /* notifications are best-effort */ }
};

const COMMISSION_RATE = 0.2; // platform takes 20% (see Settings.commission_rate)

const mapDealRow = (d) => {
  const escrowHeld = (d.escrow && d.escrow.held_amount) || d.bid_amount || 0;
  const commission = Math.round(escrowHeld * COMMISSION_RATE);
  const netPayable = (d.escrow && d.escrow.net_payable) || (escrowHeld - commission);
  return {
    deal_id: d.deal_id,
    id: d.deal_id,
    campaign_title: d.campaign_title,
    title: d.campaign_title,
    campaign: { title: d.campaign_title, budget: d.bid_amount, brand_handle: d.brand_handle },
    brand: { id: String(d.brand_id), handle: d.brand_handle, name: d.brand_name },
    creator: { id: String(d.creator_id), handle: d.creator_handle, nickname: d.creator_name },
    brand_handle: d.brand_handle,
    creator_handle: d.creator_handle,
    business_id: String(d.brand_id),
    creator_id: String(d.creator_id),
    current_state: d.current_state,
    amount: d.bid_amount,
    escrow_amount: escrowHeld,
    commission_rate: COMMISSION_RATE,
    commission_amount: commission,
    creator_payout: netPayable,
    flagged: isExceptionState(d.current_state) || !!(d.dispute && d.dispute.status),
    deadline_countdown_hours: hoursUntil(d.next_deadline_at),
    content_submission: { versions: (d.content && d.content.versions) || [] },
    content_versions: (d.content && d.content.versions) || [],
    messages: (d.messages || []).map((m) => ({ sender_nickname: m.sender_name, message: m.message, timestamp: m.created_at, admin: m.sender_type === 'admin' })),
    admin_notes: []
  };
};

// Map the embedded shipment + receipt into the shape the admin Deal drawer expects.
const mapDealShipment = (d) => {
  const s = d.shipment;
  if (!s || (!s.tracking_id && !s.courier && !s.requested_at)) return null;
  return {
    tracking_number: s.tracking_id,
    courier_name: s.courier,
    courier_status: s.courier_status,
    status: s.courier_status,
    shipped_at: s.shipped_at,
    delivered_at: s.delivered_at,
    received_at: d.receipt && d.receipt.received_at,
    address: s.ship_address || s.ship_city || null
  };
};

// Build the detail payload (brief, transition timeline, financials, shipping) on top of the row.
const mapDealDetail = (d) => {
  const escrowHeld = (d.escrow && d.escrow.held_amount) || d.bid_amount || 0;
  const commission = Math.round(escrowHeld * COMMISSION_RATE);
  const netPayable = (d.escrow && d.escrow.net_payable) || (escrowHeld - commission);
  return {
    ...mapDealRow(d),
    brief: {
      title: d.campaign_title,
      brief_text: (d.brief_sections || []).map((b) => `${b.title}\n${b.content || ''}`).join('\n\n') || null,
      per_video_budget: d.bid_amount
    },
    transitions: (d.activity_feed || [])
      .slice()
      .reverse()
      .map((a) => ({ to_state: a.event_type, reason: a.message, timestamp: a.timestamp, actor_name: a.actor_name })),
    shipment: mapDealShipment(d),
    payout_schedule: [{
      label: 'Net payout to creator',
      amount: netPayable,
      date: d.escrow && d.escrow.estimated_payout_at,
      status: d.escrow && d.escrow.status === 'released' ? 'paid' : 'pending'
    }]
  };
};

// ---------- DEALS ----------
app.get('/api/admin/deals', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    let deals = await Deal.find().sort({ updatedAt: -1 }).lean();
    deals = await scopeDealsByCategory(req, deals);
    res.json(deals.map(mapDealRow));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/deals/:id', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const d = await Deal.findOne({ deal_id: req.params.id }).lean();
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    const notes = await AdminLog.find({ module: 'deals', action: 'note_added', target_id: d.deal_id }).sort({ createdAt: -1 }).lean();
    res.json({ ...mapDealDetail(d), admin_notes: notes.map((n) => ({ note: n.detail || n.reason_text, author: `admin:${String(n.admin_id).slice(-6)}`, created_at: n.createdAt })) });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Read-only brand profile for the deal room (ops/admin). Same field shape the
// brand sees on their own Settings page, fetched by user id.
app.get('/api/admin/business/:id/profile', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const id = req.params.id;
    let u = null;
    try { u = await User.findById(id).lean(); } catch (e) { /* not a valid ObjectId */ }
    if (!u) u = await User.findOne({ $or: [{ username: id }, { public_id: id }] }).lean();
    if (!u) return res.status(404).json({ detail: 'Business not found' });
    const p = u.profile || {};
    res.json({
      brand_name: p.business_name || u.nickname || u.full_name || '',
      contact_person: p.contact_person || u.full_name || u.nickname || '',
      work_email: p.business_email || u.email || '',
      phone_number: p.phone || u.phone || '',
      website_url: p.website || '',
      logo_url: p.logo || u.profile_photo || '',
      username: u.username || '',
      role: u.role || 'business',
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/deals/:id/force-transition', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const { to_state, reason, reason_code, notify_parties } = req.body;
    if (!to_state) return res.status(400).json({ detail: 'to_state is required' });
    if (!reason || !String(reason).trim()) return res.status(400).json({ detail: 'A written justification is required' });
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    const before = d.current_state;
    d.current_state = to_state;
    d.state_started_at = new Date();
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'force_transition', message: `Forced state → ${to_state}: ${reason}` });
    await d.save();
    await writeAdminLog(req, { action: 'deal.force_transition', module: 'deals', target_type: 'deal', target_id: d.deal_id, before: { state: before }, after: { state: to_state }, reason_code: reason_code || '', reason_text: reason || '' });
    if (notify_parties !== false) {
      await notifyParties(d, { title: 'Deal status updated by support', body: `Your deal "${d.campaign_title}" was moved to "${to_state}".`, type: 'deal_force_transition' });
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Release escrow to the creator early (credits their wallet, closes the deal).
app.post('/api/admin/deals/:id/release-payment', adminAuth, requireCap('release_payouts'), async (req, res) => {
  try {
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (d.escrow && d.escrow.status === 'released') return res.status(400).json({ detail: 'Escrow already released' });
    const held = (d.escrow && d.escrow.held_amount) || d.bid_amount || 0;
    const net = (d.escrow && d.escrow.net_payable) || Math.round(held * (1 - COMMISSION_RATE));
    const before = d.current_state;
    d.escrow.status = 'released';
    d.escrow.net_payable = net;
    d.escrow.released_at = new Date();
    d.current_state = 'Paid - Complete';
    d.state_started_at = new Date();
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'payment_released', message: `Escrow released early to creator (₹${net})` });
    await d.save();
    await User.findByIdAndUpdate(d.creator_id, { $inc: { wallet_balance: net } });
    await writeAdminLog(req, { action: 'deal.release_payment', module: 'deals', target_type: 'deal', target_id: d.deal_id, before: { state: before }, after: { state: 'Paid - Complete' }, meta: { amount: net } });
    await notifyParties(d, { party: 'creator', title: 'Payment released', body: `₹${net} for "${d.campaign_title}" has been released to your wallet.`, type: 'payment_released', critical: true });
    await notifyParties(d, { party: 'brand', title: 'Escrow released', body: `Support released the escrow for "${d.campaign_title}" to the creator.`, type: 'payment_released' });
    res.json({ success: true, amount: net });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Refund the escrow to the brand and close the deal.
app.post('/api/admin/deals/:id/refund', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (d.escrow && d.escrow.status === 'refunded') return res.status(400).json({ detail: 'Escrow already refunded' });
    const held = (d.escrow && d.escrow.held_amount) || d.bid_amount || 0;
    const amount = Number(req.body.amount) > 0 ? Number(req.body.amount) : held;
    const before = d.current_state;
    d.escrow.status = 'refunded';
    d.escrow.released_at = new Date();
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'refunded', message: `Escrow refunded to brand (₹${amount})${req.body.reason ? ` — ${req.body.reason}` : ''}` });
    await d.save();
    await User.findByIdAndUpdate(d.brand_id, { $inc: { wallet_balance: amount } });
    await writeAdminLog(req, { action: 'deal.refund', module: 'deals', target_type: 'deal', target_id: d.deal_id, before: { state: before }, reason_text: req.body.reason || '', meta: { amount } });
    await notifyParties(d, { title: 'Deal refunded by support', body: `The escrow for "${d.campaign_title}" was refunded to the brand.`, type: 'deal_refunded', critical: true });
    res.json({ success: true, amount });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Open a dispute on behalf of the parties (admin-initiated).
app.post('/api/admin/deals/:id/raise-dispute', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const reason = (req.body.reason || '').trim();
    if (!reason) return res.status(400).json({ detail: 'A reason is required' });
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (!isExceptionState(d.current_state)) d.state_before_exception = d.current_state;
    d.dispute = { status: 'open', raised_by: 'admin', reason, resolution: null, resolved_at: null };
    if (EXCEPTION_STATES.includes('Disputed')) d.current_state = 'Disputed';
    d.state_started_at = new Date();
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'dispute_raised', message: `Dispute opened on behalf of the parties: ${reason}` });
    d.action_cards.push({ type: 'raise_dispute', title: 'Dispute opened by support', message: reason, created_by: 'admin' });
    await d.save();
    await writeAdminLog(req, { action: 'deal.raise_dispute', module: 'disputes', target_type: 'deal', target_id: d.deal_id, reason_text: reason });
    await notifyParties(d, { title: 'Dispute opened', body: `Support opened a dispute on "${d.campaign_title}".`, type: 'dispute_raised', critical: true });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Post an admin "intervention" message into the deal room.
app.post('/api/admin/deals/:id/message', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const message = (req.body.message || '').trim();
    if (!message) return res.status(400).json({ detail: 'A message is required' });
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    d.messages.push({ sender_type: 'admin', sender_name: 'Support', message });
    await d.save();
    await writeAdminLog(req, { action: 'deal.message', module: 'deals', target_type: 'deal', target_id: d.deal_id, detail: message });
    await notifyParties(d, { title: 'Support posted in your deal room', body: message.slice(0, 140), type: 'deal_message' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Send a notification to one or both parties from the admin console.
app.post('/api/admin/deals/:id/notify', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const message = (req.body.message || '').trim();
    const party = ['brand', 'creator', 'both'].includes(req.body.party) ? req.body.party : 'both';
    if (!message) return res.status(400).json({ detail: 'A message is required' });
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    await notifyParties(d, { party, title: 'Message from support', body: message, type: 'deal_admin_contact' });
    await writeAdminLog(req, { action: 'deal.notify', module: 'deals', target_type: 'deal', target_id: d.deal_id, detail: message, meta: { party } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/deals/:id/notes', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    await writeAdminLog(req, { action: 'note_added', module: 'deals', target_type: 'deal', target_id: req.params.id, detail: req.body.note || '' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- DISPUTES ----------
// Side-store for dispute admin metadata not modelled on the Deal (keeps Deal schema untouched)
const disputeMetaSchema = new mongoose.Schema({
  deal_id: { type: String, unique: true, index: true },
  assigned_to: { type: String, default: null },
  assigned_to_name: { type: String, default: null },
  severity: { type: String, default: 'normal' },
  peer_review_status: { type: String, default: null }, // null | requested | approved
  appeal_status: { type: String, default: null },      // null | open
  ruling_draft: { type: mongoose.Schema.Types.Mixed, default: null },
  evidence_uploads: { type: [mongoose.Schema.Types.Mixed], default: [] }
}, { timestamps: true });
const DisputeMeta = mongoose.models.DisputeMeta || mongoose.model('DisputeMeta', disputeMetaSchema);
const getMeta = async (dealId) => {
  let m = await DisputeMeta.findOne({ deal_id: dealId });
  if (!m) m = await DisputeMeta.create({ deal_id: dealId });
  return m;
};

const toDisputeRow = (d) => {
  const status = d.dispute && d.dispute.status === 'resolved' ? 'resolved' : 'open';
  const slaTarget = new Date(new Date(d.state_started_at || d.createdAt).getTime() + 48 * 36e5);
  const remaining = Math.round((slaTarget.getTime() - Date.now()) / 36e5);
  return {
    id: d.deal_id,
    business_id: String(d.brand_id),
    creator_id: String(d.creator_id),
    dispute_type: /damag/i.test(d.current_state || '') ? 'damaged_product' : 'general',
    severity: 'normal',
    created_at: d.state_started_at || d.createdAt,
    status,
    sla_breached: status !== 'resolved' && remaining < 0,
    sla_hours_remaining: remaining
  };
};

const mergeMeta = (row, m) => ({
  ...row,
  severity: (m && m.severity) || row.severity || 'normal',
  assigned_to: (m && m.assigned_to) || null,
  assigned_to_name: (m && m.assigned_to_name) || null,
  peer_review_status: (m && m.peer_review_status) || null
});

app.get('/api/admin/disputes', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const query = { $or: [{ 'dispute.status': { $ne: null } }, { current_state: { $in: EXCEPTION_STATES } }] };
    let deals = await Deal.find(query).sort({ updatedAt: -1 }).lean();
    deals = await scopeDealsByCategory(req, deals);
    const metas = await DisputeMeta.find({ deal_id: { $in: deals.map((d) => d.deal_id) } }).lean();
    const metaMap = Object.fromEntries(metas.map((m) => [m.deal_id, m]));
    let rows = deals.map((d) => mergeMeta(toDisputeRow(d), metaMap[d.deal_id]));
    const open_count = rows.filter((r) => r.status === 'open').length;
    if (req.query.status) rows = rows.filter((r) => r.status === req.query.status);
    res.json({ disputes: rows, open_count });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// NOTE: must precede '/:id' so 'appeals' is not captured as an id param
app.get('/api/admin/disputes/appeals', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const metas = await DisputeMeta.find({ appeal_status: 'open' }).lean();
    const ids = metas.map((m) => m.deal_id);
    const deals = ids.length ? await Deal.find({ deal_id: { $in: ids } }).lean() : [];
    const metaMap = Object.fromEntries(metas.map((m) => [m.deal_id, m]));
    const appeals = deals.map((d) => ({ ...mergeMeta(toDisputeRow(d), metaMap[d.deal_id]), status: 'appealed' }));
    res.json({ appeals });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/disputes/:id', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const d = await Deal.findOne({ deal_id: req.params.id }).lean();
    if (!d) return res.status(404).json({ detail: 'Dispute not found' });
    const m = await getMeta(req.params.id);
    const row = mergeMeta(toDisputeRow(d), m);
    res.json({
      dispute: {
        ...row,
        reason: (d.dispute && d.dispute.reason) || null,
        description: (d.dispute && d.dispute.reason) || null,
        ruling: (d.dispute && d.dispute.resolution) || null,
        reasoning: (d.dispute && d.dispute.resolution) || null,
        refund_amount: 0,
        creator_amount: (d.escrow && d.escrow.net_payable) || 0,
        peer_review_status: m.peer_review_status || null
      },
      ruling_draft: m.ruling_draft || null,
      evidence_uploads: (m.evidence_uploads && m.evidence_uploads.length)
        ? m.evidence_uploads
        : (d.action_cards || []).flatMap((c) => (c.attachment_urls || []).map((u) => ({ url: u, label: c.title || c.type, uploaded_by: c.created_by }))),
      brief: { title: d.campaign_title, brief_text: (d.brief_sections || []).map((b) => `${b.title}: ${b.content}`).join('\n'), per_video_budget: d.bid_amount, budget_max: d.bid_amount },
      timeline: (d.activity_feed || []).map((a) => ({ timestamp: a.timestamp, actor_name: a.actor_name, actor_type: a.actor_type, message: a.message, event_type: a.event_type })),
      chat_history: (d.messages || []).map((m) => ({ sender_id: m.sender_name, content: m.message })),
      content_versions: (d.content && d.content.versions) || [],
      shipment: { tracking_number: d.shipment && d.shipment.tracking_id, courier_name: d.shipment && d.shipment.courier, courier_status: d.shipment && d.shipment.courier_status, status: d.shipment && d.shipment.courier_status, received_at: d.receipt && d.receipt.received_at },
      prior_disputes: []
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/disputes/:id/rule', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const { ruling, refund_amount, creator_amount, reasoning, extension_days, note_to_creator, note_to_brand, penalty_amount, penalty_party } = req.body;
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Dispute not found' });
    // Enforce the per-role dispute ceiling (Ops Regular ₹25K, Ops Senior ₹1L, Founder ∞).
    const cap = disputeCap(req.user.admin_role);
    const disputeValue = Math.max(Number(refund_amount) || 0, Number(creator_amount) || 0, d.bid_amount || 0);
    if (disputeValue > cap) {
      return res.status(403).json({ detail: `This dispute (₹${disputeValue.toLocaleString('en-IN')}) exceeds your ₹${cap.toLocaleString('en-IN')} resolution limit. Escalate to a senior admin or founder.` });
    }
    if (!d.dispute) d.dispute = {};
    d.dispute.status = 'resolved';
    d.dispute.resolution = `${ruling}: ${reasoning}`;
    d.dispute.resolved_at = new Date();
    if (d.escrow) {
      d.escrow.status = ruling === 'favor_brand' ? 'refunded' : 'released';
      if (creator_amount) d.escrow.net_payable = Number(creator_amount);
    }
    if (d.state_before_exception) d.current_state = d.state_before_exception;
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'dispute_ruling', message: `Ruling: ${ruling}. ${reasoning}` });
    if (note_to_creator) d.messages.push({ sender_type: 'admin', sender_name: adminName(req), message: `[To creator] ${note_to_creator}` });
    if (note_to_brand) d.messages.push({ sender_type: 'admin', sender_name: adminName(req), message: `[To brand] ${note_to_brand}` });
    await d.save();
    await DisputeMeta.updateOne({ deal_id: req.params.id }, { $set: { ruling_draft: null } });
    await writeAdminLog(req, { action: 'dispute.ruling', module: 'disputes', target_type: 'dispute', target_id: d.deal_id, after: { ruling, refund_amount, creator_amount, extension_days, penalty_amount, penalty_party, note_to_creator, note_to_brand }, reason_text: reasoning || '' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/disputes/:id/assign', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const m = await getMeta(req.params.id);
    m.assigned_to = String(req.user.id);
    m.assigned_to_name = adminName(req);
    await m.save();
    await writeAdminLog(req, { action: 'dispute.assigned', module: 'disputes', target_type: 'dispute', target_id: req.params.id, after: { assigned_to: m.assigned_to } });
    res.json({ success: true, assigned_to_name: m.assigned_to_name });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/disputes/:id/ruling-draft', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const m = await getMeta(req.params.id);
    m.ruling_draft = req.body;
    await m.save();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/disputes/:id/request-review', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const m = await getMeta(req.params.id);
    m.peer_review_status = 'requested';
    m.ruling_draft = req.body;
    await m.save();
    await writeAdminLog(req, { action: 'dispute.peer_review_requested', module: 'disputes', target_type: 'dispute', target_id: req.params.id });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/disputes/:id/request-info', adminAuth, requireCap('rule_disputes'), async (req, res) => {
  try {
    const { party, message } = req.body;
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Dispute not found' });
    d.messages.push({ sender_type: 'admin', sender_name: adminName(req), message: `[Info requested from ${party}] ${message}` });
    await d.save();
    await writeAdminLog(req, { action: 'dispute.info_requested', module: 'disputes', target_type: 'dispute', target_id: d.deal_id, detail: `from ${party}`, reason_text: message || '' });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- SHIPPING ----------
// Reuse the shared /uploads dir + multer for manual Shiprocket label PDFs (11.9)
const fs = require('fs');
const multer = require('multer');
const SHIP_UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(SHIP_UPLOAD_DIR)) fs.mkdirSync(SHIP_UPLOAD_DIR, { recursive: true });
const shippingUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, SHIP_UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safe = (file.originalname || 'label').replace(/[^a-zA-Z0-9._-]/g, '_');
      cb(null, `label-${Date.now()}-${Math.round(Math.random() * 1e6)}-${safe}`);
    }
  }),
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB — labels are small PDFs/images
});

app.get('/api/admin/shipping/requests', adminAuth, requireCap('manage_shipping'), async (req, res) => {
  try {
    let deals = await Deal.find({ current_state: { $regex: /awaiting shipment|shipped|in transit/i } }).sort({ state_started_at: 1 }).lean();
    deals = await scopeDealsByCategory(req, deals);
    res.json(deals.map((d) => {
      const s = d.shipment || {};
      return {
        id: d.deal_id,
        deal_id: d.deal_id,
        campaign_title: d.campaign_title,
        brand_handle: d.brand_handle,
        creator_handle: d.creator_handle,
        requested_at: s.requested_at || d.state_started_at || d.createdAt,
        status: s.shipped_at ? 'shipped' : 'pending',
        courier: s.courier || '',
        tracking_number: s.tracking_id || '',
        // PRD 11.9 queue fields
        product_summary: s.product_summary || d.campaign_title || '',
        weight: s.weight || '',
        dimensions: s.dimensions || '',
        pickup_address: s.pickup_address || '',   // brand pickup (internal only)
        ship_address: s.ship_address || '',       // creator shipping (internal only)
        ship_city: s.ship_city || '',
        label_url: s.label_url || ''
      };
    }));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/shipping/:id/label', adminAuth, requireCap('manage_shipping'), shippingUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ detail: 'No label file uploaded' });
    const fileUrl = `/uploads/${req.file.filename}`;
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (!d.shipment) d.shipment = {};
    d.shipment.label_url = fileUrl;
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'label_uploaded', message: 'Shipping label uploaded to Deal Room' });
    await d.save();
    await writeAdminLog(req, { action: 'shipping.label_uploaded', module: 'shipping', target_type: 'deal', target_id: req.params.id, after: { label_url: fileUrl } });
    res.status(201).json({ success: true, file_url: fileUrl });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/shipping/:id/ship', adminAuth, requireCap('manage_shipping'), async (req, res) => {
  try {
    const { courier, tracking_number, label_url } = req.body;
    const d = await Deal.findOne({ deal_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (!d.shipment) d.shipment = {};
    d.shipment.courier = courier;
    d.shipment.tracking_id = tracking_number;
    d.shipment.courier_status = 'shipped';
    d.shipment.shipped_at = new Date();
    if (label_url) d.shipment.label_url = label_url;
    if (Array.isArray(DEAL_STATES) && DEAL_STATES[1]) d.current_state = DEAL_STATES[1];
    d.activity_feed.push({ actor_type: 'admin', actor_name: adminName(req), event_type: 'shipped', message: `Shipped via ${courier} (${tracking_number})` });
    await d.save();
    await writeAdminLog(req, { action: 'shipping.shipped', module: 'shipping', target_type: 'deal', target_id: d.deal_id, after: { courier, tracking_number, label_url } });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- ESCROW ----------
app.get('/api/admin/escrow', adminAuth, requireCap('view_financials'), async (req, res) => {
  try {
    const deals = await Deal.find({ 'escrow.held_amount': { $gt: 0 } }).lean();
    res.json(deals.map((d) => ({
      id: d.deal_id,
      deal_id: d.deal_id,
      campaign_title: d.campaign_title,
      brand_handle: d.brand_handle,
      creator_handle: d.creator_handle,
      amount: (d.escrow && d.escrow.held_amount) || 0,
      held_amount: (d.escrow && d.escrow.held_amount) || 0,
      status: (d.escrow && d.escrow.status) || 'held'
    })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- WALLET ADJUST + WITHDRAWAL ACTIONS ----------
app.post('/api/admin/wallet/adjust', adminAuth, requireCap('adjust_wallet'), async (req, res) => {
  try {
    const { user_id, amount, reason } = req.body;
    const u = await User.findById(user_id);
    if (!u) return res.status(404).json({ detail: 'User not found' });
    const before = u.wallet_balance || 0;
    u.wallet_balance = before + Number(amount);
    await u.save();
    await writeAdminLog(req, { action: 'wallet.adjust', module: 'financials', target_type: 'user', target_id: String(user_id), before: { balance: before }, after: { balance: u.wallet_balance }, reason_text: reason || '' });
    res.json({ success: true, new_balance: u.wallet_balance });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/admin/withdrawals/:id/approve', adminAuth, requireCap('release_payouts'), async (req, res) => {
  await writeAdminLog(req, { action: 'withdrawal.approved', module: 'financials', target_type: 'withdrawal', target_id: req.params.id });
  res.json({ success: true });
});
app.post('/api/admin/withdrawals/:id/reject', adminAuth, requireCap('release_payouts'), async (req, res) => {
  await writeAdminLog(req, { action: 'withdrawal.rejected', module: 'financials', target_type: 'withdrawal', target_id: req.params.id, reason_text: req.query.reason || '' });
  res.json({ success: true });
});

// ---------- AUDIT LOG (PRD 11.15) ----------
// Sensitive actions trigger a founder email digest and are flagged in the UI.
const SENSITIVE_ACTIONS = [
  'wallet.adjust', 'dispute.ruling', 'user.banned', 'user.suspended',
  'settings.update', 'withdrawal.approved', 'withdrawal.rejected', 'deal.force_transition'
];

const buildAuditFilter = (req) => {
  const filter = {};
  if (req.query.action) filter.action = req.query.action;
  if (req.query.module) filter.module = req.query.module;
  if (req.query.admin_id) filter.admin_id = req.query.admin_id;
  if (req.query.target_id) filter.target_id = req.query.target_id;
  if (req.query.from || req.query.to) {
    filter.createdAt = {};
    if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
    if (req.query.to) filter.createdAt.$lte = new Date(`${req.query.to}T23:59:59.999Z`);
  }
  // Log review (PRD 11.15): the founder sees everything; other admins see their
  // own actions plus peers' routine (non-sensitive) actions.
  if (req.user.role !== 'admin') {
    filter.$or = [
      { admin_id: req.user.id },
      { action: { $nin: SENSITIVE_ACTIONS } }
    ];
  }
  return filter;
};

const mapAuditRow = (l) => ({
  id: String(l._id),
  created_at: l.createdAt,
  admin_nickname: l.admin_email || `admin:${String(l.admin_id).slice(-6)}`,
  admin_id: String(l.admin_id),
  admin_role: l.admin_role || '',
  action: l.action,
  module: l.module || '',
  target_type: l.target_type || '',
  target_id: l.target_id,
  before: l.before ?? null,
  after: l.after ?? null,
  reason: l.reason_text || l.detail || '',
  ip: l.ip_address || '',
  user_agent: l.user_agent || '',
  sensitive: SENSITIVE_ACTIONS.includes(l.action)
});

app.get('/api/admin/audit-logs', adminAuth, requireCap('view_audit'), async (req, res) => {
  try {
    const logs = await AdminLog.find(buildAuditFilter(req)).sort({ createdAt: -1 }).limit(500).lean();
    res.json({ logs: logs.map(mapAuditRow) });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/audit-logs/export', adminAuth, requireCap('view_audit'), async (req, res) => {
  try {
    const logs = await AdminLog.find(buildAuditFilter(req)).sort({ createdAt: -1 }).limit(5000).lean();
    sendCsv(res, `audit-log_${new Date().toISOString().split('T')[0]}.csv`,
      ['timestamp', 'admin', 'role', 'action', 'module', 'target', 'before', 'after', 'reason', 'ip'],
      logs.map((l) => {
        const r = mapAuditRow(l);
        return [r.created_at, r.admin_nickname, r.admin_role, r.action, r.module,
          r.target_type ? `${r.target_type}:${r.target_id}` : '', JSON.stringify(r.before),
          JSON.stringify(r.after), r.reason, r.ip];
      }));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- SETTINGS ----------
app.get('/api/admin/settings', adminAuth, requireCap('edit_settings'), async (req, res) => {
  try {
    let s = await Settings.findOne({ key: 'platform' });
    if (!s) s = await Settings.create({ key: 'platform' });
    res.json({ settings: s });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.put('/api/admin/settings', adminAuth, requireCap('edit_settings'), async (req, res) => {
  try {
    const before = await Settings.findOne({ key: 'platform' }).lean();
    const s = await Settings.findOneAndUpdate({ key: 'platform' }, { $set: req.body }, { new: true, upsert: true });
    await writeAdminLog(req, { action: 'settings.update', module: 'settings', target_type: 'setting', target_id: 'platform', before, after: s.toObject(), reason_text: 'Settings updated' });
    res.json({ settings: s });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ---------- EXPORTS (CSV) ----------
const sendCsv = (res, name, header, rows) => {
  const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
  const csv = [header.join(','), ...rows.map((r) => r.map(esc).join(','))].join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
  res.send(csv);
};

app.get('/api/admin/deals/export', adminAuth, requireCap('manage_deals'), async (req, res) => {
  try {
    const deals = await Deal.find().lean();
    sendCsv(res, 'deals.csv', ['deal_id', 'campaign', 'brand', 'creator', 'state', 'amount'],
      deals.map((d) => [d.deal_id, d.campaign_title, d.brand_handle, d.creator_handle, d.current_state, d.bid_amount]));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/users/export', adminAuth, requireCap('user_management'), async (req, res) => {
  try {
    const users = await User.find().lean();
    sendCsv(res, 'users.csv', ['id', 'nickname', 'email', 'role', 'status', 'balance'],
      users.map((u) => [u._id, u.nickname, u.email, u.role, u.approval_status, u.wallet_balance || 0]));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/admin/payment-transactions/export', adminAuth, requireCap('view_financials'), async (req, res) => sendCsv(res, 'transactions.csv', ['id', 'amount', 'status'], []));
app.get('/api/admin/reports/digest', adminAuth, requireCap('generate_reports'), async (req, res) => sendCsv(res, 'digest.csv', ['metric', 'value'], [['period', req.query.period || 'daily'], ['generated_at', new Date().toISOString()]]));
app.get('/api/admin/financials/tds/export', adminAuth, requireCap('export_tax'), async (req, res) => sendCsv(res, 'tds.csv', ['creator', 'gross', 'tds', 'net'], []));
app.get('/api/admin/financials/gst/export', adminAuth, requireCap('export_tax'), async (req, res) => sendCsv(res, 'gst.csv', ['invoice', 'taxable', 'gst'], []));

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'API is running',
    timestamp: new Date().toISOString()
  });
});

// ===========================================================================
// Additional endpoints the frontend calls. Implemented against the User model
// where meaningful; safe empty responses where a feature has no data model yet
// (so pages render their empty state instead of 404ing).
// ===========================================================================
const photoStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, path.join(__dirname, 'uploads')),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${(file.originalname || 'photo').replace(/[^a-zA-Z0-9._-]/g, '_')}`)
});
const photoUpload = multer({ storage: photoStorage, limits: { fileSize: 25 * 1024 * 1024 } }).any();

// ---- Profile management (creator + shared) ----
app.patch('/api/profile/portfolio', auth, async (req, res) => {
  try {
    const portfolio = Array.isArray(req.body) ? req.body : (req.body.portfolio || []);
    await User.findByIdAndUpdate(req.user.id, { $set: { portfolio } });
    res.json({ message: 'Portfolio updated', count: portfolio.length });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.put('/api/profile/update-info', auth, async (req, res) => {
  try {
    const src = { ...req.query, ...req.body };
    const u = await User.findById(req.user.id);
    if (!u) return res.status(404).json({ detail: 'User not found' });
    const profile = { ...(u.profile || {}) };
    ['bio', 'description', 'gender', 'country', 'age_range', 'languages'].forEach((f) => {
      if (src[f] !== undefined) profile[f] = (f === 'languages' && typeof src[f] === 'string') ? src[f].split(',').map((s) => s.trim()).filter(Boolean) : src[f];
    });
    u.profile = profile; u.markModified('profile');
    await u.save();
    res.json({ message: 'Profile updated' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.put('/api/profile/payment-info', auth, async (req, res) => {
  try {
    const u = await User.findById(req.user.id);
    if (!u) return res.status(404).json({ detail: 'User not found' });
    u.profile = { ...(u.profile || {}), payment_info: { ...((u.profile || {}).payment_info || {}), ...req.body, ...req.query } };
    u.markModified('profile');
    await u.save();
    res.json({ message: 'Payment info saved' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/profile/change-password', auth, async (req, res) => {
  try {
    const src = { ...req.query, ...req.body };
    if (!src.old_password || !src.new_password) return res.status(400).json({ detail: 'old_password and new_password are required' });
    const u = await User.findById(req.user.id).select('+password');
    if (!u) return res.status(404).json({ detail: 'User not found' });
    if (!(await u.comparePassword(src.old_password))) return res.status(400).json({ detail: 'Current password is incorrect' });
    u.password = src.new_password; // hashed by pre-save hook
    await u.save();
    res.json({ message: 'Password changed' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.post('/api/profile/upload-photo', auth, (req, res) => photoUpload(req, res, async (err) => {
  if (err) return res.status(400).json({ detail: err.message });
  try {
    const file = (req.files && req.files[0]) || null;
    if (!file) return res.status(400).json({ detail: 'No file uploaded' });
    const url = `/uploads/${file.filename}`;
    await User.findByIdAndUpdate(req.user.id, { $set: { profile_photo: url } });
    res.json({ profile_photo: url, file_url: url });
  } catch (e) { res.status(500).json({ detail: e.message }); }
}));

app.post('/api/profile/upload-banner', auth, (req, res) => photoUpload(req, res, async (err) => {
  if (err) return res.status(400).json({ detail: err.message });
  try {
    const file = (req.files && req.files[0]) || null;
    if (!file) return res.status(400).json({ detail: 'No file uploaded' });
    const url = `/uploads/${file.filename}`;
    await User.findByIdAndUpdate(req.user.id, { $set: { banner: url } });
    res.json({ banner: url, file_url: url });
  } catch (e) { res.status(500).json({ detail: e.message }); }
}));

// Deactivate: hide the account (active:false). Reactivated on next login.
app.post('/api/profile/deactivate', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { $set: { active: false } });
    res.json({ message: 'Account deactivated' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Delete: permanently remove the account.
app.delete('/api/profile', auth, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);
    res.json({ message: 'Account deleted' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

app.get('/api/profile/2fa/status', auth, (req, res) => res.json({ enabled: false }));
app.post('/api/profile/2fa/setup', auth, (req, res) => res.status(501).json({ detail: 'Two-factor auth is not available on this server yet' }));
app.post('/api/profile/2fa/verify', auth, (req, res) => res.status(501).json({ detail: 'Two-factor auth is not available on this server yet' }));
app.post('/api/profile/2fa/disable', auth, (req, res) => res.json({ message: 'Two-factor disabled' }));

// ---- Reviews / bids (no data models yet → empty) ----
app.get('/api/reviews', auth, (req, res) => res.json([]));
app.get('/api/reviews/creator/:id', auth, async (req, res) => {
  try { const u = await User.findById(req.params.id).select('reviews').lean(); res.json((u && u.reviews) || []); }
  catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/reviews', auth, async (req, res) => {
  try {
    const { campaign_id, creator_id, rating, review } = req.body;
    if (!creator_id) return res.status(400).json({ detail: 'creator_id required' });
    const entry = { campaign_id, creator_id, reviewer_id: req.user.id, rating: Number(rating) || 0, review: review || '', created_at: new Date() };
    const u = await User.findById(creator_id);
    if (!u) return res.status(404).json({ detail: 'Creator not found' });
    u.reviews = [...(u.reviews || []), entry];
    u.total_reviews = u.reviews.length;
    u.average_rating = Number((u.reviews.reduce((s, r) => s + (Number(r.rating) || 0), 0) / u.reviews.length).toFixed(2));
    u.markModified('reviews');
    await u.save();
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Creator's own bids — derived from campaigns whose bids array includes them.
app.get('/api/bids/my', auth, async (req, res) => {
  try {
    const campaigns = await Campaign.find({ 'bids.creator_id': req.user.id }).lean();
    res.json(campaigns.map((c) => {
      const my = (c.bids || []).find((b) => String(b.creator_id) === String(req.user.id)) || {};
      return { ...c, id: c._id, campaign: { ...c, id: c._id }, my_bid: my, bid_status: my.status || 'pending', submitted_at: my.submitted_at };
    }));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Creator: submit / update a bid on a campaign ─────────────────────────────
app.post('/api/campaigns/:id/bid', auth, async (req, res) => {
  try {
    const { amount, proposal, estimated_delivery_days } = req.body;
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    const bid = { creator_id: req.user.id, amount: Number(amount) || 0, proposal: proposal || '', estimated_delivery_days: Number(estimated_delivery_days) || 0, status: 'pending', submitted_at: new Date() };
    c.bids = c.bids || [];
    const idx = c.bids.findIndex((b) => String(b.creator_id) === String(req.user.id));
    if (idx >= 0) c.bids[idx] = bid; else c.bids.push(bid);
    c.markModified('bids');
    await c.save();
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Create (idempotently) the Deal that backs the Deal Room for a campaign+creator.
// Without it the campaign shows under "My Active Work" but the Deal Room is empty.
async function ensureDealForCampaign(c, creatorId, brandId) {
  const Deal = require('./models/Deal');
  const sm = require('./utils/dealStateMachine');
  const existing = await Deal.findOne({ campaign_id: c._id, creator_id: creatorId });
  if (existing) return existing;
  const creator = await User.findById(creatorId).lean();
  const brand = await User.findById(brandId).lean();
  const bid = (c.bids || []).find((b) => String(b.creator_id) === String(creatorId));
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

// ── Brand: select a creator's bid (query or body creator_id) ─────────────────
app.post('/api/campaigns/:id/select-creator', auth, async (req, res) => {
  try {
    const creatorId = req.query.creator_id || req.body.creator_id;
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    c.selected_creator = creatorId;
    c.status = 'in_progress';
    const bid = (c.bids || []).find((b) => String(b.creator_id) === String(creatorId));
    if (bid) { bid.status = 'selected'; c.escrow_amount = bid.amount || c.budget_max || 0; }
    c.markModified('bids');
    await c.save();
    const creator = await User.findById(creatorId).lean();
    const amount = (bid && bid.amount) || c.budget_max || 0;
    try { await ensureDealForCampaign(c, creatorId, req.user.id); } catch (e) { /* non-blocking */ }
    res.json({ success: true, creator_nickname: (creator && (creator.username ? `@${creator.username}` : creator.nickname)) || 'Creator', amount });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Brand: save a draft campaign + edit a campaign ───────────────────────────
app.post('/api/campaigns/draft', auth, async (req, res) => {
  try {
    const c = await Campaign.create({ ...req.body, business_id: req.user.id, status: 'draft' });
    res.status(201).json({ ...c.toObject(), id: c._id });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.patch('/api/campaigns/:id', auth, async (req, res) => {
  try {
    const body = { ...req.body }; delete body._id; delete body.id; delete body.business_id;
    const c = await Campaign.findByIdAndUpdate(req.params.id, { $set: body }, { new: true });
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    res.json({ ...c.toObject(), id: c._id });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Work: creator submit, brand review (approve / request revision) ──────────
app.post('/api/work/submit', auth, async (req, res) => {
  try {
    const { campaign_id, work_files, description } = req.body;
    const c = await Campaign.findById(campaign_id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    c.status = 'work_submitted';
    c.work_submission = { creator_id: req.user.id, work_files: work_files || [], description: description || '', status: 'pending_review', submitted_at: new Date() };
    c.markModified('work_submission');
    await c.save();
    res.status(201).json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.get('/api/work/:id', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id).lean();
    if (!c || !c.work_submission) return res.status(404).json({ detail: 'Work not found' });
    let creator_nickname = c.work_submission.creator_nickname;
    try {
      const cr = await User.findById(c.work_submission.creator_id).select('nickname username').lean();
      if (cr) creator_nickname = cr.username ? `@${cr.username}` : cr.nickname;
    } catch (e) { /* best-effort */ }
    const approved = c.work_submission.status === 'approved' || c.status === 'completed';
    res.json({
      id: c._id, campaign_id: c._id, campaign_title: c.title, business_id: c.business_id,
      ...c.work_submission,
      creator_nickname,
      watermark_protected: !approved,        // clean original only after approval
      can_download: approved                 // brand can pull the clean file once approved
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Brand downloads the clean (non-watermarked) deliverable — only after approval.
app.get('/api/work/:id/download', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id).lean();
    if (!c || !c.work_submission) return res.status(404).json({ detail: 'Work not found' });
    if (String(c.business_id) !== String(req.user.id) && req.user.role !== 'admin')
      return res.status(403).json({ detail: 'Only the brand owner can download this deliverable' });
    if (!(c.work_submission.status === 'approved' || c.status === 'completed'))
      return res.status(403).json({ detail: 'Download unlocks after you approve the work' });

    const files = c.work_submission.work_files || [];
    const fileUrl = files.find((f) => /\.(mp4|mov|webm|m4v|avi|mkv)$/i.test(String(f).split('?')[0])) || files[0];
    if (!fileUrl) return res.status(404).json({ detail: 'No file available to download' });
    if (/^https?:\/\//i.test(fileUrl)) return res.redirect(fileUrl); // already external

    const rel = String(fileUrl).replace(/^\/+/, '');
    const abs = path.join(__dirname, rel);
    // Confine to the uploads dir (no path traversal).
    if (!abs.startsWith(path.join(__dirname, 'uploads'))) return res.status(400).json({ detail: 'Invalid file path' });
    const ext = rel.split('.').pop();
    const safeName = `${(c.title || 'deliverable').replace(/[^\w.-]+/g, '_')}.${ext}`;
    return res.download(abs, safeName);
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/work/:id/approve', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    c.status = 'completed';
    if (c.work_submission) { c.work_submission.status = 'approved'; c.markModified('work_submission'); }
    await c.save();
    // Sync the deal: approve content + release escrow to the creator.
    try {
      const Deal = require('./models/Deal');
      const sm = require('./utils/dealStateMachine');
      const deal = await Deal.findOne({ campaign_id: c._id });
      if (deal && deal.current_state === sm.STATES.AWAITING_REVIEW) {
        sm.approveContent(deal, { actor_name: 'Brand' });
        sm.releasePayment(deal, { actor_name: 'System' });
        await deal.save();
      }
    } catch (e) { /* non-blocking */ }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/work/:id/request-revision', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    const feedback = req.query.feedback || req.body.feedback || '';
    c.status = 'in_progress';
    if (c.work_submission) { c.work_submission.status = 'revision_requested'; c.work_submission.feedback = feedback; c.markModified('work_submission'); }
    await c.save();
    // Sync the deal: move back to Revision Requested with the brand's feedback.
    try {
      const Deal = require('./models/Deal');
      const sm = require('./utils/dealStateMachine');
      const deal = await Deal.findOne({ campaign_id: c._id });
      if (deal && deal.current_state === sm.STATES.AWAITING_REVIEW) {
        if (deal.revision) { deal.revision.latest_feedback = feedback; deal.revision.revision_count_used = (deal.revision.revision_count_used || 0) + 1; }
        const latest = deal.content.versions[deal.content.versions.length - 1];
        if (latest) latest.status = 'revision_requested';
        sm.transition(deal, sm.STATES.REVISION_REQUESTED, { actor_type: 'brand', actor_name: 'Brand', event_type: 'revision_requested', message: feedback ? `Brand requested a revision: ${feedback}` : 'Brand requested a revision.' });
        await deal.save();
      }
    } catch (e) { /* non-blocking */ }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Shipment (tied to a campaign) ────────────────────────────────────────────
// Brand's shipment view reads the canonical Deal.shipment (the same record the
// admin shipping queue works on). The creator's delivery address is never exposed.
app.get('/api/shipment/:id', auth, async (req, res) => {
  try {
    const d = await Deal.findOne({ campaign_id: req.params.id }).lean();
    const s = (d && d.shipment) || {};
    const received_at = (d && d.receipt && d.receipt.received_at) || null;
    const status = s.courier_status || (s.requested_at ? 'requested' : null);
    const receipt = (d && d.receipt) || {};
    res.json({
      id: req.params.id,
      status,                                     // requested | shipped | delivered | null
      requested: !!s.requested_at,
      tracking_number: s.tracking_id || null,
      courier_name: s.courier || null,
      courier_slip: s.courier_slip || null,
      shipment_checklist: s.shipment_checklist || {},
      label_url: s.label_url || null,
      expected_delivery: s.expected_delivery_at || null,
      shipped_at: s.shipped_at || null,
      product_summary: s.product_summary || null,
      weight: s.weight || null,
      dimensions: s.dimensions || null,
      pickup_address: s.pickup_address || null,   // brand's own pickup — fine to show
      received: !!received_at,
      received_at,
      unboxing_video: receipt.unboxing_video_url || null,
      dispute: receipt.items_damaged ? { reason: receipt.damage_report || '' } : null,
      // ship_address (creator delivery) intentionally omitted
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/shipment/update', auth, async (req, res) => {
  try {
    // Write to the Deal.shipment — the SAME place GET /shipment/:id and /receive use,
    // so a brand-entered tracking number actually persists and shows up.
    const { campaign_id, tracking_number, courier_slip, expected_delivery, shipment_checklist } = req.body;
    if (campaign_id) {
      const d = await Deal.findOne({ campaign_id });
      if (d) {
        if (!d.shipment) d.shipment = {};
        if (tracking_number) d.shipment.tracking_id = tracking_number;
        if (courier_slip) d.shipment.courier_slip = courier_slip;
        if (expected_delivery) d.shipment.expected_delivery_at = expected_delivery;
        if (shipment_checklist) d.shipment.shipment_checklist = shipment_checklist;
        // Adding tracking means it's on the way — advance to shipped unless already delivered.
        if (d.shipment.courier_status !== 'delivered') {
          d.shipment.courier_status = 'shipped';
          d.shipment.shipped_at = d.shipment.shipped_at || new Date();
        }
        d.shipment.updated_at = new Date();
        d.markModified('shipment');
        await d.save();
      }
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/shipment/receive', auth, async (req, res) => {
  try {
    const { campaign_id, unboxing_video, items_damaged, dispute_reason } = req.body;
    if (campaign_id) {
      const d = await Deal.findOne({ campaign_id });
      if (d) {
        d.receipt = { ...(d.receipt || {}), received_at: new Date(), unboxing_video_url: unboxing_video || (d.receipt && d.receipt.unboxing_video_url) || null, items_damaged: !!items_damaged, damage_report: items_damaged ? (dispute_reason || '') : null };
        if (!d.shipment) d.shipment = {};
        d.shipment.courier_status = 'delivered';
        d.shipment.delivered_at = new Date();
        d.markModified('receipt'); d.markModified('shipment');
        await d.save();
      }
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// Build a Shiprocket-ready delivery address from a creator's saved profile.
// Defensive: handles a structured profile.address object OR the flat signup fields.
function creatorDeliveryAddress(u) {
  if (!u) return null;
  const p = u.profile || {};
  const addr = p.address;
  const obj = (addr && typeof addr === 'object') ? addr : {};
  const built = {
    full_name: p.fullName || p.full_name || u.full_name || u.nickname || '',
    phone: obj.phone || p.phone || u.phone || '',
    line1: obj.line1 || (typeof addr === 'string' ? addr : '') || '',
    line2: obj.line2 || '',
    city: obj.city || p.city || '',
    state: obj.state || p.state || '',
    pincode: obj.pincode || p.pincode || '',
    country: obj.country || p.country || 'India',
  };
  if (!built.line1 || !built.pincode) return null;   // not enough to ship
  return built;
}

// Render an address object into the single-line string the admin queue displays.
function formatShipAddress(a) {
  if (!a) return '';
  const line = [a.line1, a.line2, a.city, [a.state, a.pincode].filter(Boolean).join(' ')].filter(Boolean).join(', ');
  const who = [a.full_name, a.phone].filter(Boolean).join(' · ');
  return who ? `${who}\n${line}` : line;
}

// Brand: submit product + pickup details → creates a shipment REQUEST on the Deal.
// The admin shipping queue then generates the label (manual Shiprocket) and ships.
// The creator's delivery address is captured server-side for ops and NEVER shown
// to the brand.
app.post('/api/deals/:id/request-shipment', auth, async (req, res) => {
  try {
    const d = await Deal.findOne({ campaign_id: req.params.id });
    if (!d) return res.status(404).json({ detail: 'Deal not found' });
    if (String(d.brand_id) !== String(req.user.id)) return res.status(403).json({ detail: 'Not authorized for this deal' });

    let creator = null;
    try { creator = await User.findById(d.creator_id).lean(); } catch (e) { /* uuid id */ }
    // The creator's delivery address is NOT the brand's concern — don't block the brand on it.
    // If it isn't set yet, accept the request anyway; the creator/platform fills it in before dispatch.
    const delivery = creatorDeliveryAddress(creator);

    const { description, weight, dimensions, pickup_address } = req.body;
    const dims = dimensions && (dimensions.length || dimensions.width || dimensions.height)
      ? `${dimensions.length || '?'}×${dimensions.width || '?'}×${dimensions.height || '?'} cm` : '';

    d.shipment = {
      ...(d.shipment ? d.shipment.toObject ? d.shipment.toObject() : d.shipment : {}),
      required: true,
      requested_at: new Date(),
      product_summary: description || '',
      weight: weight ? `${weight} kg` : '',
      dimensions: dims,
      pickup_address: formatShipAddress(pickup_address),   // brand pickup (internal)
      ship_address: delivery ? formatShipAddress(delivery) : '',   // creator delivery (internal) — may be filled later
      ship_city: delivery ? (delivery.city || '') : '',
      awaiting_creator_address: !delivery,                 // platform/creator completes address before dispatch
      courier_status: 'requested',
    };
    d.activity_feed.push({ actor_type: 'brand', actor_name: d.brand_name || 'Brand', event_type: 'shipment_requested', message: 'Brand submitted product & pickup details. Awaiting label from the platform.', timestamp: new Date() });
    d.markModified('shipment');
    await d.save();

    res.json({ message: 'Shipment requested', status: 'requested' });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Brand: invite a creator from the directory ───────────────────────────────
app.post('/api/business/creator-directory/:id/invite', auth, async (req, res) => {
  try {
    const Thread = require('./models/Thread');
    const Message = require('./models/Message');
    const creatorId = req.params.id;

    const creator = await User.findById(creatorId).select('_id').lean();
    if (!creator) return res.status(404).json({ detail: 'Creator not found' });
    const brand = await User.findById(req.user.id).select('nickname username profile').lean();
    const brandName = (brand && (brand.username ? `@${brand.username}` : brand.nickname)) || (brand && brand.profile && brand.profile.business_name) || 'A brand';

    // Deliver the invitation INTO the creator's chat as a private_invitation
    // action card (a bare Notification never surfaces in Messages).
    const pairKey = Thread.pairKey(req.user.id, creatorId);
    let thread = await Thread.findOne({ pair_key: pairKey });
    if (!thread) {
      thread = await Thread.create({
        participants: [req.user.id, creatorId],
        pair_key: pairKey,
        initiated_by: req.user.id,
        unread: {}
      });
    }

    const card = await Message.create({
      thread_id: thread._id,
      item_type: 'action_card',
      sender_id: req.user.id,
      recipient_id: creatorId,
      type: 'private_invitation',
      fields: {
        campaign_name: req.body.campaign_name || 'Private campaign',
        deliverable_summary: req.body.deliverable_summary || 'As described in the brief',
        budget: req.body.budget || 0,
        timeline: req.body.timeline || 'As agreed',
        usage_rights: req.body.usage_rights || 'As agreed',
        notes: req.body.message || '',
        campaign_id: req.body.campaign_id || null
      },
      card_status: 'open',
      expires_at: new Date(Date.now() + 72 * 3600 * 1000)
    });
    thread.last_message = { message: '[private invitation]', sender_id: req.user.id, item_type: 'action_card', attachment_urls: [], timestamp: card.createdAt };
    thread.unread.set(String(creatorId), (thread.unread.get(String(creatorId)) || 0) + 1);
    thread.typing.set(String(req.user.id), new Date(0));
    await thread.save();

    try {
      await Notification.create({
        user_id: String(creatorId),
        type: 'private_invitation',
        title: `Private invitation from ${brandName}`,
        body: req.body.message || `${brandName} invited you to collaborate.`
      });
    } catch (e) { /* non-blocking */ }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Mark a single notification read (both path styles the UI uses) ───────────
app.patch('/api/notifications/:id', auth, async (req, res) => {
  try { await Notification.findByIdAndUpdate(req.params.id, { $set: { read: true } }); res.json({ success: true }); }
  catch (e) { res.status(500).json({ detail: e.message }); }
});
app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try { await Notification.findByIdAndUpdate(req.params.id, { $set: { read: true } }); res.json({ success: true }); }
  catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Brief: submit/advance a draft campaign for approval ──────────────────────
app.post('/api/campaigns/:id/submit', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });
    if (c.status === 'draft') c.status = 'pending_approval';
    await c.save();
    res.json({ ...c.toObject(), id: c._id });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Shortlist for a campaign (curated approved creators) ─────────────────────
app.get('/api/campaigns/:id/shortlist', auth, async (req, res) => {
  try {
    const c = await Campaign.findById(req.params.id).lean();
    const cat = (c && (c.category || '')).toString().toLowerCase();
    let creators = await User.find({ role: 'creator', approval_status: 'approved', profile_completed: true }).limit(12).lean();
    // Prefer creators in the brief's category when one is set.
    if (cat) {
      const inCat = creators.filter((u) => categoryOf(u) && (categoryOf(u).includes(normCat(cat)) || normCat(cat).includes(categoryOf(u))));
      if (inCat.length) creators = inCat;
    }
    const invited = (c && c.shortlist_invites) || [];
    res.json(creators.map((u) => ({
      creator_id: String(u._id),
      nickname: u.nickname,
      username: u.username,
      public_creator_id: u.public_creator_id,
      profile_photo: u.profile_photo,
      category: u.category || (u.profile || {}).category || (u.profile || {}).niche || '',
      profile: u.profile || {},
      invited: invited.includes(String(u._id))
    })));
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Brand: send a Private Invitation to a shortlisted creator ────────────────
app.post('/api/campaigns/:id/shortlist/:creatorId/invite', auth, async (req, res) => {
  try {
    const Thread = require('./models/Thread');
    const Message = require('./models/Message');
    const { creatorId } = req.params;
    const c = await Campaign.findById(req.params.id);
    if (!c) return res.status(404).json({ detail: 'Campaign not found' });

    const brand = await User.findById(req.user.id).select('nickname username profile').lean();
    const creator = await User.findById(creatorId).select('_id').lean();
    if (!creator) return res.status(404).json({ detail: 'Creator not found' });
    const brandName = (brand && (brand.username ? `@${brand.username}` : brand.nickname)) || (brand && brand.profile && brand.profile.business_name) || 'A brand';

    c.shortlist_invites = [...new Set([...(c.shortlist_invites || []), String(creatorId)])];
    c.markModified('shortlist_invites');
    await c.save();

    // Deliver the invitation INTO the creator's chat as a private_invitation
    // action card — this is what the creator's Messages page reads from (a bare
    // Notification never surfaces in chat, so the creator could not act on it).
    const pairKey = Thread.pairKey(req.user.id, creatorId);
    let thread = await Thread.findOne({ pair_key: pairKey });
    if (!thread) {
      thread = await Thread.create({
        participants: [req.user.id, creatorId],
        pair_key: pairKey,
        initiated_by: req.user.id,
        unread: {}
      });
    }

    const budget = c.budget_max || c.budget_min || 0;
    const card = await Message.create({
      thread_id: thread._id,
      item_type: 'action_card',
      sender_id: req.user.id,
      recipient_id: creatorId,
      type: 'private_invitation',
      fields: {
        campaign_name: c.title,
        deliverable_summary: c.deliverables || req.body.brief || 'As described in the brief',
        budget,
        timeline: c.due_date ? new Date(c.due_date).toLocaleDateString('en-IN') : 'As agreed',
        usage_rights: 'As agreed',
        notes: req.body.message || '',
        campaign_id: String(c._id)
      },
      card_status: 'open',
      expires_at: new Date(Date.now() + 72 * 3600 * 1000) // 72h, matches chat policy
    });
    thread.last_message = { message: '[private invitation]', sender_id: req.user.id, item_type: 'action_card', attachment_urls: [], timestamp: card.createdAt };
    thread.unread.set(String(creatorId), (thread.unread.get(String(creatorId)) || 0) + 1);
    thread.typing.set(String(req.user.id), new Date(0));
    await thread.save();

    // Also drop a bell notification (works for any id type).
    try {
      await Notification.create({
        user_id: String(creatorId),
        type: 'private_invitation',
        title: `Private invitation from ${brandName}`,
        body: req.body.message || `${brandName} invited you to their campaign "${c.title}".`
      });
    } catch (e) { /* non-blocking */ }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Brand: request a fresh shortlist (manual curation) ───────────────────────
app.post('/api/campaigns/:id/shortlist/request-new', auth, async (req, res) => res.json({ success: true, message: 'New shortlist requested' }));

// ── Gig wishlist (toggle + count) ────────────────────────────────────────────
const Gig = require('./models/Gig');
app.get('/api/gigs/:id/wishlist', auth, async (req, res) => {
  try {
    const g = await Gig.findById(req.params.id).select('wishlist').lean();
    const list = (g && g.wishlist) || [];
    res.json({ count: list.length, is_wishlisted: list.includes(String(req.user.id)) });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.post('/api/gigs/:id/wishlist', auth, async (req, res) => {
  try {
    const g = await Gig.findById(req.params.id);
    if (!g) return res.status(404).json({ detail: 'Gig not found' });
    const uid = String(req.user.id);
    g.wishlist = g.wishlist || [];
    const i = g.wishlist.indexOf(uid);
    if (i >= 0) g.wishlist.splice(i, 1); else g.wishlist.push(uid);
    await g.save();
    res.json({ count: g.wishlist.length, is_wishlisted: i < 0 });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});

// ── Admin: gateway edit/delete, wallet txns, escrow & payout actions ─────────
app.patch('/api/admin/notification-gateway/:id', adminAuth, requireCap('edit_settings'), (req, res) => res.json({ success: true }));
app.delete('/api/admin/notification-gateway/:id', adminAuth, requireCap('edit_settings'), (req, res) => res.json({ success: true }));
app.patch('/api/admin/payment-gateway/:id', adminAuth, requireCap('edit_settings'), (req, res) => res.json({ success: true }));
app.delete('/api/admin/payment-gateway/:id', adminAuth, requireCap('edit_settings'), (req, res) => res.json({ success: true }));
app.get('/api/admin/wallet/:id/transactions', adminAuth, requireCap('view_financials'), (req, res) => res.json([]));
app.post('/api/admin/escrow/:id/:action', adminAuth, requireCap('release_payouts'), (req, res) => res.json({ success: true }));
app.post('/api/admin/payouts/:id/hold', adminAuth, requireCap('release_payouts'), (req, res) => res.json({ success: true }));
app.post('/api/admin/payouts/:id/release', adminAuth, requireCap('release_payouts'), (req, res) => res.json({ success: true }));

// ---- Withdrawals / payouts ----
app.get('/api/withdrawal/history', auth, (req, res) => res.json([]));
app.post('/api/withdrawal/request', auth, (req, res) => res.status(201).json({ success: true, message: 'Withdrawal requested' }));
app.get('/api/payout/overview', auth, async (req, res) => {
  try {
    // Compute the creator's earnings from their deals so a "Paid - Complete"
    // deal shows up in Available Balance / Paid this month / All-time earnings.
    const deals = await Deal.find({ creator_id: req.user.id }).lean();
    const earn = (d) => Number(d.escrow?.net_payable) || Number(d.bid_amount) || 0;
    const isPaid = (d) => d.current_state === 'Paid - Complete' || d.escrow?.status === 'released';
    const isEscrow = (d) => !isPaid(d)
      && ['held', 'queued'].includes(d.escrow?.status)
      && !String(d.current_state || '').toLowerCase().includes('cancel');

    const now = new Date();
    const inThisMonth = (d) => {
      const raw = d.escrow?.released_at || d.updatedAt;
      const dt = raw ? new Date(raw) : null;
      return dt && dt.getMonth() === now.getMonth() && dt.getFullYear() === now.getFullYear();
    };

    const paid = deals.filter(isPaid);
    const allTime = paid.reduce((s, d) => s + earn(d), 0);
    const paidThisMonth = paid.filter(inThisMonth).reduce((s, d) => s + earn(d), 0);
    const pending = deals.filter(isEscrow).reduce((s, d) => s + earn(d), 0);

    res.json({
      balance: allTime,           // available to withdraw (no withdrawals tracked yet)
      pending_release: pending,
      paid_this_month: paidThisMonth,
      all_time_earnings: allTime,
      last_month: 0,
      deals_paid: paid.length,
    });
  } catch (e) { res.status(500).json({ detail: e.message }); }
});
app.get('/api/payout-ranges', auth, (req, res) => res.json({ ranges: [] }));

// ---- Categories ----
app.get('/api/categories', (req, res) => res.json(CATEGORY_LIST || []));

// ---- Notifications ----
app.get('/api/notifications/my-notifications', auth, async (req, res) => {
  try { res.json(await Notification.find({ user_id: req.user.id }).sort({ createdAt: -1 }).limit(50).lean()); }
  catch { res.json([]); }
});
app.get('/api/notifications/unread-count', auth, async (req, res) => {
  try { res.json({ count: await Notification.countDocuments({ user_id: req.user.id, read: false }) }); }
  catch { res.json({ count: 0 }); }
});
app.post('/api/notifications/mark-all-read', auth, async (req, res) => {
  try { await Notification.updateMany({ user_id: req.user.id, read: false }, { $set: { read: true } }); res.json({ success: true }); }
  catch { res.json({ success: true }); }
});

// ---- Business settings (back the brand Settings page from the user profile) ----
app.get('/api/business/settings/profile', auth, async (req, res) => {
  const u = await User.findById(req.user.id).lean(); const p = (u && u.profile) || {};
  res.json({ brand_name: p.business_name || (u && u.nickname) || '', contact_person: p.contact_person || (u && u.full_name) || '', work_email: p.business_email || (u && u.email) || '', phone: p.phone || '', website: p.website || '', logo: p.logo || (u && u.profile_photo) || '' });
});
app.put('/api/business/settings/profile', auth, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.status(404).json({ detail: 'Not found' });
  u.profile = { ...(u.profile || {}), ...req.body }; u.markModified('profile'); await u.save(); res.json({ success: true });
});
app.get('/api/business/settings/company', auth, async (req, res) => {
  const u = await User.findById(req.user.id).lean(); const p = (u && u.profile) || {};
  res.json({ business_type: p.business_type || '', gstin: p.gstin || '', business_category: p.industry_category || p.industry || '', country: p.country || '', billing_address: p.billing_address || '', city: p.city || '', state: p.state || '' });
});
app.put('/api/business/settings/company', auth, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.status(404).json({ detail: 'Not found' });
  u.profile = { ...(u.profile || {}), ...req.body }; u.markModified('profile'); await u.save(); res.json({ success: true });
});
app.get('/api/business/settings/team', auth, (req, res) => res.json([]));
app.post('/api/business/settings/team/invite', auth, (req, res) => res.json({ success: true }));
app.get('/api/business/settings/billing', auth, (req, res) => res.json({ plan: 'Free', commission_rate: 10, next_billing_date: null, monthly_budget: { used: 0, total: 0 } }));
app.get('/api/business/settings/notifications', auth, (req, res) => res.json({ new_applications: true, deal_updates: true, payment_alerts: true, messages: true, weekly_reports: true }));
app.put('/api/business/settings/notifications', auth, (req, res) => res.json({ success: true }));
app.get('/api/business/settings/summary', auth, async (req, res) => {
  const u = await User.findById(req.user.id).lean();
  res.json({ plan: 'Free', wallet_balance: (u && u.wallet_balance) || 0, team_count: 1 });
});
app.post('/api/business/settings/logo', auth, (req, res) => photoUpload(req, res, async (err) => {
  if (err) return res.status(400).json({ detail: err.message });
  const file = (req.files && req.files[0]) || null;
  if (!file) return res.json({ success: true });
  const url = `/uploads/${file.filename}`;
  const u = await User.findById(req.user.id);
  if (u) { u.profile = { ...(u.profile || {}), logo: url }; u.markModified('profile'); await u.save(); }
  res.json({ success: true, logo: url });
}));
app.delete('/api/business/settings/logo', auth, async (req, res) => {
  const u = await User.findById(req.user.id);
  if (u) { u.profile = { ...(u.profile || {}), logo: '' }; u.markModified('profile'); await u.save(); }
  res.json({ success: true });
});

// ---- Admin endpoints still referenced by the panel (safe placeholders) ----
app.post('/api/admin/assign-campaign', adminAuth, requireCap('review_applications'), (req, res) => res.json({ success: true }));
app.get('/api/admin/payouts', adminAuth, requireCap('view_financials'), (req, res) => res.json(DEMO.payouts));
app.post('/api/admin/payouts/batch-release', adminAuth, requireCap('release_payouts'), (req, res) => res.json({ success: true }));
app.get('/api/admin/financials/revenue', adminAuth, requireCap('view_financials'), (req, res) => res.json({
  revenue: 196000, commission: 39200, escrow: 47000,
  series: [
    { label: 'Mon', value: 18000 }, { label: 'Tue', value: 24000 }, { label: 'Wed', value: 15000 },
    { label: 'Thu', value: 31000 }, { label: 'Fri', value: 42000 }, { label: 'Sat', value: 38000 }, { label: 'Sun', value: 28000 }
  ]
}));
app.get('/api/admin/financials/overview', adminAuth, requireCap('view_financials'), (req, res) => res.json({
  gross_revenue: 196000, platform_commission: 39200, creator_payouts: 156800,
  in_escrow: 47000, pending_withdrawals: 15500, tds_collected: 7840, gst_collected: 35280
}));
app.get('/api/admin/filter-rules', adminAuth, requireCap('content_moderation'), (req, res) => res.json(DEMO.filterRules));
app.post('/api/admin/filter-rules/propose', adminAuth, requireCap('content_moderation'), (req, res) => res.json({ success: true }));
app.post('/api/admin/message/moderate', adminAuth, requireCap('content_moderation'), (req, res) => res.json({ success: true }));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

// Error handling middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
