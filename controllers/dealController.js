const mongoose = require('mongoose');
const Deal = require('../models/Deal');
const sm = require('../utils/dealStateMachine');
const { STATES: S } = sm;

// Frontend reads err.response?.data?.detail, so error bodies use { detail }.
const fail = (res, status, detail) => res.status(status).json({ detail });

function displayName(user) {
  return user?.nickname || user?.full_name || user?.name || user?.email || 'User';
}

/**
 * Load a deal by its human deal_id and authorise the caller. Returns
 * { deal, viewerParty } or sends an error response and returns null.
 *
 * The :dealId in the URL is also accepted as a CAMPAIGN id. The brand's Work
 * Review page lists campaigns (it reads campaign.work_submission) and posts the
 * campaign's id to these deal endpoints — which 404'd with "Deal not found",
 * because a deal_id looks like "UGC-1234567-2", never an ObjectId. Resolving the
 * campaign to its deal here fixes approve / request-revision from that page
 * without every caller having to know which id it is holding.
 */
async function loadDealForUser(req, res) {
  const key = String(req.params.dealId || '');
  let deal = await Deal.findOne({ deal_id: key });
  if (!deal && mongoose.Types.ObjectId.isValid(key)) {
    // Newest first: a campaign that was re-run would otherwise resolve to a stale deal.
    deal = await Deal.findOne({ campaign_id: key }).sort({ createdAt: -1 });
  }
  if (!deal) {
    fail(res, 404, 'Deal not found');
    return null;
  }

  const uid = String(req.user.id);
  let viewerParty = null;
  if (String(deal.creator_id) === uid) viewerParty = 'creator';
  else if (String(deal.brand_id) === uid) viewerParty = 'brand';
  else if (req.user.role === 'admin') viewerParty = 'admin';

  if (!viewerParty) {
    fail(res, 403, 'You are not a participant in this deal');
    return null;
  }

  // Apply any pending time-based transitions before acting/reading (6.6).
  if (sm.applyTimeouts(deal)) await deal.save();

  return { deal, viewerParty };
}

function actorFrom(req, viewerParty) {
  return { actor_type: viewerParty, actor_name: displayName(req.user) };
}

// Auto-notification in chat for state changes (6.7).
function systemChat(deal, message) {
  deal.messages.push({ sender_type: 'system', sender_name: 'System', message, created_at: new Date() });
}

/**
 * Mirror a content decision onto the campaign's work_submission.
 *
 * Two parallel records track the same piece of work: Deal.content.versions (the
 * deal state machine) and Campaign.work_submission (what the brand's Work Review
 * list and the creator's dashboard actually read). server.js already syncs
 * campaign -> deal; without this, a decision taken through a /api/deals endpoint
 * left the campaign stale, so the creator was never told a revision was wanted.
 * Best-effort: a bookkeeping miss must not fail the brand's action.
 */
async function syncCampaignWork(deal, { workStatus, campaignStatus, feedback, requestedChanges }) {
  try {
    if (!deal.campaign_id) return;
    const Campaign = require('../models/Campaign');
    const c = await Campaign.findById(deal.campaign_id);
    if (!c || !c.work_submission) return;
    c.work_submission.status = workStatus;
    if (feedback !== undefined) c.work_submission.feedback = feedback;
    if (requestedChanges !== undefined) c.work_submission.requested_changes = requestedChanges;
    c.markModified('work_submission');
    if (campaignStatus) c.status = campaignStatus;
    await c.save();
  } catch (e) {
    console.error('[deals] could not sync campaign work_submission:', e.message);
  }
}

// --- Reads ------------------------------------------------------------------

// GET /api/deals/my  -> array (role-aware: creator | brand)
exports.myDeals = async (req, res, next) => {
  try {
    const uid = req.user.id;
    let filter;
    let viewerParty;
    if (req.user.role === 'admin') {
      filter = {};
      viewerParty = 'admin';
    } else if (req.user.role === 'business') {
      filter = { brand_id: uid };
      viewerParty = 'brand';
    } else {
      filter = { creator_id: uid };
      viewerParty = 'creator';
    }

    const deals = await Deal.find({ ...filter, archived_by: { $ne: uid } }).sort({ updatedAt: -1 });

    // Fire time-based transitions on read so the 5-day timer always lands.
    await Promise.all(
      deals.map(async (d) => {
        if (sm.applyTimeouts(d)) await d.save();
      })
    );

    res.json(deals.map((d) => sm.serializeDeal(d, viewerParty)));
  } catch (err) {
    next(err);
  }
};

// GET /api/deals/:dealId -> single
exports.getDeal = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    res.json(sm.serializeDeal(ctx.deal, ctx.viewerParty));
  } catch (err) {
    next(err);
  }
};

// GET /api/deals  (admin only) -> all deals, optional ?state=
exports.listAllDeals = async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.state) filter.current_state = req.query.state;
    const deals = await Deal.find(filter).sort({ updatedAt: -1 });
    res.json(deals.map((d) => sm.serializeDeal(d, 'admin')));
  } catch (err) {
    next(err);
  }
};

// --- Brand actions ----------------------------------------------------------

// POST /api/deals/:dealId/tracking  (state 1 -> 2)
exports.uploadTracking = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'brand') return fail(res, 403, 'Only the brand can upload tracking');
    if (deal.current_state !== S.AWAITING_SHIPMENT)
      return fail(res, 409, `Action not allowed in state: ${deal.current_state}`);

    const { tracking_id, courier, courier_tracking_url, expected_delivery_at } = req.body;
    if (!tracking_id) return fail(res, 400, 'Tracking ID is required');

    deal.shipment.tracking_id = tracking_id;
    deal.shipment.courier = courier || deal.shipment.courier;
    deal.shipment.courier_tracking_url = courier_tracking_url || null;
    deal.shipment.courier_status = 'In Transit';
    deal.shipment.shipped_at = new Date();
    deal.shipment.expected_delivery_at = expected_delivery_at ? new Date(expected_delivery_at) : null;

    sm.transition(deal, S.IN_TRANSIT, {
      ...actorFrom(req, viewerParty),
      event_type: 'shipped',
      message: `Brand uploaded tracking ID: ${tracking_id}`
    });
    systemChat(deal, `Brand uploaded tracking ID: ${tracking_id}`);

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/delivered  (state 2 -> 3) courier/admin/brand
exports.markDelivered = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (deal.current_state !== S.IN_TRANSIT)
      return fail(res, 409, `Action not allowed in state: ${deal.current_state}`);

    deal.shipment.courier_status = 'Delivered';
    deal.shipment.delivered_at = new Date();
    sm.transition(deal, S.AWAITING_RECEIPT, {
      actor_type: 'system',
      actor_name: 'Courier',
      event_type: 'delivered',
      message: 'Courier marked the package delivered.'
    });
    systemChat(deal, 'Courier marked the package delivered.');

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/approve  (state 5 -> 7 -> 8)
exports.approve = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'brand') return fail(res, 403, 'Only the brand can approve');
    // last-write-wins recheck (6.10): state is re-validated before completing.
    if (deal.current_state !== S.AWAITING_REVIEW)
      return fail(res, 409, `Action resolved: deal is now "${deal.current_state}".`);

    sm.approveContent(deal, { actor_name: displayName(req.user) });
    systemChat(deal, 'Brand approved the content. Payment queued.');

    // Atomically finalise: watermark removal + escrow release (6.9).
    const watermarkFailed = req.body?.simulate_watermark_failure === true;
    sm.releasePayment(deal, { watermarkFailed });
    if (!watermarkFailed) systemChat(deal, `Payment released. Deal complete.`);

    await deal.save();
    await syncCampaignWork(deal, { workStatus: 'approved', campaignStatus: 'completed' });
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/request-revision  (state 5 -> 6)
exports.requestRevision = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'brand') return fail(res, 403, 'Only the brand can request a revision');
    if (deal.current_state !== S.AWAITING_REVIEW)
      return fail(res, 409, `Action resolved: deal is now "${deal.current_state}".`);

    const used = deal.revision.revision_count_used || 0;
    const limit = deal.revision.revision_limit || 0;
    if (used >= limit)
      return fail(res, 409, `Revision limit reached (${used} of ${limit} used). Approve or raise a dispute.`);

    const { feedback, requested_changes, new_deadline_at } = req.body;
    if (!feedback || !String(feedback).trim()) return fail(res, 400, 'Revision feedback is required');

    deal.revision.revision_count_used = used + 1;
    deal.revision.latest_feedback = feedback;
    deal.revision.requested_changes = Array.isArray(requested_changes) ? requested_changes : [];
    deal.revision.new_deadline_at = new_deadline_at ? new Date(new_deadline_at) : new Date(Date.now() + 72 * 3600 * 1000);

    const latest = deal.content.versions[deal.content.versions.length - 1];
    if (latest) latest.status = 'revision_requested';

    sm.transition(deal, S.REVISION_REQUESTED, {
      ...actorFrom(req, viewerParty),
      event_type: 'revision_requested',
      message: `Brand requested revision (${deal.revision.revision_count_used} of ${limit} used).`
    });
    systemChat(deal, `Brand requested revision (${deal.revision.revision_count_used} of ${limit} used).`);

    await deal.save();
    // Put the feedback where the creator will actually see it (their dashboard
    // and Work Review both read the campaign's work_submission, not the deal).
    await syncCampaignWork(deal, {
      workStatus: 'revision_requested',
      campaignStatus: 'in_progress',
      feedback,
      requestedChanges: deal.revision.requested_changes,
    });
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// --- Creator actions --------------------------------------------------------

// POST /api/deals/:dealId/receipt  (state 3 -> 4, or -> Damaged)
exports.submitReceipt = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'creator') return fail(res, 403, 'Only the creator can confirm receipt');
    // Accept from In Transit too (no courier webhook marks "delivered").
    if (![S.AWAITING_RECEIPT, S.IN_TRANSIT].includes(deal.current_state))
      return fail(res, 409, `Action not allowed in state: ${deal.current_state}`);

    const { unboxing_video_url, items_damaged, damage_report, received_at } = req.body;
    if (!unboxing_video_url && !deal.receipt.unboxing_video_url)
      return fail(res, 400, 'An unboxing video is required to mark received');

    deal.receipt.received_at = received_at ? new Date(received_at) : new Date();
    deal.receipt.unboxing_video_url = unboxing_video_url || deal.receipt.unboxing_video_url;
    deal.receipt.items_damaged = !!items_damaged;
    deal.receipt.damage_report = damage_report || null;

    if (items_damaged) {
      deal.state_before_exception = S.IN_PROGRESS;
      sm.transition(deal, S.DAMAGED, {
        ...actorFrom(req, viewerParty),
        event_type: 'damage_report',
        message: 'Creator reported a damaged / wrong product on receipt.'
      });
      systemChat(deal, 'Creator reported a damaged / wrong product. Timeline paused for admin review.');
    } else {
      sm.transition(deal, S.IN_PROGRESS, {
        ...actorFrom(req, viewerParty),
        event_type: 'received',
        message: 'Creator marked the product received and uploaded an unboxing video.'
      });
      systemChat(deal, 'Creator marked the product received.');
    }

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/content  (state 4 or 6 -> 5)
exports.submitContent = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'creator') return fail(res, 403, 'Only the creator can submit content');
    if (![S.IN_PROGRESS, S.REVISION_REQUESTED].includes(deal.current_state))
      return fail(res, 409, `Action not allowed in state: ${deal.current_state}`);

    const { video_url, caption_url, thumbnail_url, raw_footage_url, creator_note } = req.body;
    const required = (deal.content && deal.content.required_assets) || {};
    if (!video_url) return fail(res, 400, 'Final video is required');
    if (required.caption_script && !caption_url) return fail(res, 400, 'Caption/script is required');
    if (required.thumbnail && !thumbnail_url) return fail(res, 400, 'Thumbnail is required');
    if (required.raw_footage && !raw_footage_url) return fail(res, 400, 'Raw footage is required');

    const nextVersion = (deal.content.versions.length || 0) + 1;
    deal.content.versions.push({
      version: nextVersion,
      video_url,
      caption_url: caption_url || null,
      thumbnail_url: thumbnail_url || null,
      raw_footage_url: raw_footage_url || null,
      creator_note: creator_note || null,
      submitted_at: new Date(),
      status: 'pending_review'
    });

    const now = new Date();
    const timeLabel = now.toLocaleTimeString('en-IN', { hour: 'numeric', minute: '2-digit', hour12: true });
    sm.transition(deal, S.AWAITING_REVIEW, {
      ...actorFrom(req, viewerParty),
      event_type: 'content_submitted',
      message: `Creator submitted content v${nextVersion} at ${timeLabel}.`
    });
    systemChat(deal, `Creator submitted content v${nextVersion} at ${timeLabel}.`);

    await deal.save();

    // Mirror the submission onto the linked campaign so the brand's existing
    // Work Review queue (campaign-based) surfaces it. Non-blocking.
    try {
      if (deal.campaign_id) {
        const Campaign = require('../models/Campaign');
        const camp = await Campaign.findById(deal.campaign_id);
        if (camp) {
          camp.status = 'work_submitted';
          camp.work_submission = {
            creator_id: String(deal.creator_id),
            work_files: [video_url, thumbnail_url, caption_url, raw_footage_url].filter(Boolean),
            description: creator_note || '',
            status: 'pending_review',
            submitted_at: new Date(),
            deal_id: deal.deal_id,
            version: nextVersion
          };
          camp.markModified('work_submission');
          await camp.save();
        }
      }
    } catch (e) { /* mirror is best-effort */ }

    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/revision-response
exports.revisionResponse = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (viewerParty !== 'creator') return fail(res, 403, 'Only the creator can respond to a revision');

    const { response, note } = req.body;
    if (response === 'accepted') {
      sm.logEvent(deal, { ...actorFrom(req, viewerParty), event_type: 'revision_accepted', message: note || 'Creator accepted the revision request.' });
      systemChat(deal, 'Creator accepted the revision request and will resubmit.');
    } else {
      // scope_creep | partial_dispute -> escalate to admin without losing state
      deal.action_cards.push({
        type: 'escalate_to_admin',
        title: response === 'partial_dispute' ? 'Partial dispute on revision' : 'Scope creep flagged',
        message: note || 'Creator flagged the revision request.',
        created_by: 'creator'
      });
      sm.logEvent(deal, { ...actorFrom(req, viewerParty), event_type: 'revision_flagged', message: note || 'Creator flagged the revision request to admin.' });
      systemChat(deal, 'Creator flagged the revision request to admin for review.');
    }

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// --- Shared actions (either party) ------------------------------------------

// POST /api/deals/:dealId/chat
exports.sendChat = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    const { message, attachment_urls } = req.body;
    if (!message && !(attachment_urls && attachment_urls.length))
      return fail(res, 400, 'Message or attachment is required');

    deal.messages.push({
      sender_type: viewerParty,
      sender_name: displayName(req.user),
      message: message || 'Attachment sent',
      attachment_urls: attachment_urls || [],
      created_at: new Date()
    });

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/action-card
exports.createActionCard = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    const { type, message, attachment_urls } = req.body;
    if (!type) return fail(res, 400, 'Action card type is required');

    deal.action_cards.push({
      type,
      title: message || type,
      message: message || '',
      attachment_urls: attachment_urls || [],
      created_by: viewerParty
    });
    sm.logEvent(deal, { ...actorFrom(req, viewerParty), event_type: type, message: message || `${type} created` });

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/escalate
exports.escalate = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    const { message, attachment_urls } = req.body;

    deal.action_cards.push({
      type: 'escalate_to_admin',
      title: 'Escalate to Admin',
      message: message || 'Escalation requested',
      attachment_urls: attachment_urls || [],
      created_by: viewerParty
    });
    sm.logEvent(deal, { ...actorFrom(req, viewerParty), event_type: 'escalate_to_admin', message: `${viewerParty} escalated to admin.` });
    systemChat(deal, `${displayName(req.user)} escalated this deal to admin.`);

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/dispute  (-> Disputed, any state)
exports.raiseDispute = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (sm.isExceptionState(deal.current_state))
      return fail(res, 409, 'This deal is already under admin review');

    const { message, attachment_urls } = req.body;
    deal.state_before_exception = deal.current_state;
    deal.dispute = { status: 'open', raised_by: viewerParty, reason: message || 'Dispute raised', resolution: null, resolved_at: null };
    deal.escrow.status = 'held';

    deal.action_cards.push({
      type: 'raise_dispute',
      title: 'Dispute raised',
      message: message || 'Dispute raised',
      attachment_urls: attachment_urls || [],
      created_by: viewerParty
    });
    sm.transition(deal, S.DISPUTED, {
      ...actorFrom(req, viewerParty),
      event_type: 'dispute_raised',
      message: `${viewerParty} raised a dispute. Escrow held pending admin resolution.`
    });
    systemChat(deal, `${displayName(req.user)} raised a dispute. Escrow is held pending admin resolution.`);

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/damage-report  (-> Damaged)
exports.damageReport = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    const { message, attachment_urls } = req.body;

    if (!sm.isExceptionState(deal.current_state)) deal.state_before_exception = deal.current_state;
    deal.receipt.items_damaged = true;
    deal.receipt.damage_report = message || deal.receipt.damage_report || 'Damaged / wrong product reported';

    deal.action_cards.push({
      type: 'damage_report',
      title: 'Damaged / Wrong Product Reported',
      message: message || 'Damaged or wrong product reported by creator',
      attachment_urls: attachment_urls || [],
      created_by: viewerParty
    });
    sm.transition(deal, S.DAMAGED, {
      ...actorFrom(req, viewerParty),
      event_type: 'damage_report',
      message: 'Damaged / wrong product reported. Creator timeline paused, escrow held.'
    });
    systemChat(deal, 'Damaged / wrong product reported. Creator timeline paused for admin + brand review.');

    await deal.save();
    res.json(sm.serializeDeal(deal, viewerParty));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/archive
exports.archive = async (req, res, next) => {
  try {
    const ctx = await loadDealForUser(req, res);
    if (!ctx) return;
    const { deal, viewerParty } = ctx;
    if (deal.current_state !== S.PAID) return fail(res, 409, 'Only completed deals can be archived');
    if (!deal.archived_by.map(String).includes(String(req.user.id))) deal.archived_by.push(req.user.id);
    await deal.save();
    res.json({ archived: true });
  } catch (err) {
    next(err);
  }
};

// --- Admin intervention (Section 11 / 6.6 states 9, 10) ---------------------

// POST /api/deals/:dealId/resolve  (admin)
exports.adminResolve = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') return fail(res, 403, 'Admin access required');
    const deal = await Deal.findOne({ deal_id: req.params.dealId });
    if (!deal) return fail(res, 404, 'Deal not found');

    const { outcome, resolution, new_deadline_at } = req.body;
    const adminName = displayName(req.user);
    const back = deal.state_before_exception || S.IN_PROGRESS;

    if (deal.dispute && deal.dispute.status === 'open') {
      deal.dispute.status = 'resolved';
      deal.dispute.resolution = resolution || outcome;
      deal.dispute.resolved_at = new Date();
    }
    (deal.action_cards || []).forEach((c) => {
      if (['raise_dispute', 'damage_report', 'escalate_to_admin'].includes(c.type) && c.status === 'open') c.status = 'resolved';
    });

    switch (outcome) {
      case 'release_payment':
        deal.escrow.net_payable = deal.escrow.net_payable || deal.escrow.held_amount;
        deal.escrow.status = 'queued';
        sm.logEvent(deal, { actor_type: 'admin', actor_name: adminName, event_type: 'admin_resolution', message: resolution || 'Admin released payment after dispute resolution.' });
        sm.releasePayment(deal, { actor_name: adminName });
        systemChat(deal, 'Admin released payment after dispute resolution.');
        break;
      case 'refund':
        deal.escrow.status = 'refunded';
        sm.transition(deal, S.PAID, { actor_type: 'admin', actor_name: adminName, event_type: 'admin_resolution', message: resolution || 'Admin refunded the brand and closed the deal.' });
        systemChat(deal, 'Admin issued a full refund to the brand. Deal closed.');
        break;
      case 'new_deadline':
        deal.next_deadline_at = new_deadline_at ? new Date(new_deadline_at) : new Date(Date.now() + 72 * 3600 * 1000);
        sm.transition(deal, back, { actor_type: 'admin', actor_name: adminName, event_type: 'admin_resolution', message: resolution || `Admin resumed the deal with a new deadline.` });
        systemChat(deal, 'Admin resumed the deal with a new deadline.');
        break;
      case 'resume':
      default:
        sm.transition(deal, back, { actor_type: 'admin', actor_name: adminName, event_type: 'admin_resolution', message: resolution || 'Admin resolved the issue and resumed the deal.' });
        systemChat(deal, 'Admin resolved the issue and resumed the deal.');
        break;
    }

    deal.state_before_exception = null;
    await deal.save();
    res.json(sm.serializeDeal(deal, 'admin'));
  } catch (err) {
    next(err);
  }
};

// --- Dev seed ---------------------------------------------------------------

const SAMPLE_BRIEF = [
  { title: 'Campaign Goal', content: 'Drive awareness for the summer skincare launch with an authentic day-in-the-life reel.' },
  { title: 'Deliverables', content: '1 x 30-45s vertical reel, 1 thumbnail, raw footage.' },
  { title: 'Key Messages', content: 'Lightweight, non-greasy, dermatologist-tested.' },
  { title: 'Do / Don\'t', content: 'Do show texture and application. Don\'t mention competitor brands.' },
  { title: 'Tone & Style', content: 'Warm, natural light, conversational voiceover.' },
  { title: 'Hashtags & Handles', content: '#GlowDaily @glow.daily' },
  { title: 'Timeline', content: 'Shoot within 5 days of receipt; submit within 7 days.' },
  { title: 'Usage Rights', content: '90-day paid usage across brand social + whitelisting. No resale of raw footage.' }
];

// POST /api/deals/seed  (dev helper) — creates demo deals for the caller.
exports.seedDemo = async (req, res, next) => {
  try {
    const uid = req.user.id;
    const isBrand = req.user.role === 'business';
    const otherId = new (require('mongoose').Types.ObjectId)();
    const stamp = Date.now().toString().slice(-5);

    const base = (i, state, overrides = {}) => ({
      deal_id: `UGC-${stamp}-${i}`,
      campaign_title: overrides.title || `Summer Glow Reel #${i}`,
      brand_id: isBrand ? uid : otherId,
      brand_name: isBrand ? displayName(req.user) : 'Glow Daily',
      brand_handle: isBrand ? (req.user.nickname || 'mybrand') : 'glow.daily',
      creator_id: isBrand ? otherId : uid,
      creator_name: isBrand ? 'Aanya Creates' : displayName(req.user),
      creator_handle: isBrand ? 'aanya.creates' : (req.user.nickname || 'creator'),
      current_state: state,
      state_started_at: new Date(),
      next_deadline_at: new Date(Date.now() + 48 * 3600 * 1000),
      bid_amount: 12000,
      brief_sections: SAMPLE_BRIEF,
      content: { required_assets: { caption_script: true, thumbnail: true, raw_footage: true }, watermark_required_until_approval: true, versions: [] },
      revision: { revision_limit: 2, revision_count_used: 0 },
      escrow: { held_amount: 12000, net_payable: 12000, deductions: [], status: 'held' },
      activity_feed: [{ actor_type: 'system', actor_name: 'System', event_type: 'accepted', message: 'Brief accepted. Deal Room opened.', timestamp: new Date() }],
      messages: [{ sender_type: 'system', sender_name: 'System', message: 'Deal Room opened. Brief is available above.', created_at: new Date() }],
      ...overrides
    });

    const docs = [
      base(1, S.AWAITING_SHIPMENT),
      base(2, S.AWAITING_RECEIPT, {
        title: 'Unboxing & Honest Review',
        shipment: { tracking_id: 'DELHIVERY-12345678', courier: 'Delhivery', courier_status: 'Delivered', courier_tracking_url: 'https://www.delhivery.com/track', expected_delivery_at: new Date(), shipped_at: new Date(Date.now() - 2 * 86400000), delivered_at: new Date() }
      }),
      base(3, S.AWAITING_REVIEW, {
        title: 'Tutorial: 3 Looks',
        shipment: { tracking_id: 'BLUEDART-99887766', courier: 'BlueDart', courier_status: 'Delivered', delivered_at: new Date(Date.now() - 3 * 86400000) },
        receipt: { received_at: new Date(Date.now() - 3 * 86400000), unboxing_video_url: '/uploads/sample-unboxing.mp4', items_damaged: false },
        content: { required_assets: { caption_script: true, thumbnail: true, raw_footage: false }, watermark_required_until_approval: true, versions: [{ version: 1, video_url: '/uploads/sample-v1.mp4', caption_url: '/uploads/caption.txt', thumbnail_url: null, submitted_at: new Date(), status: 'pending_review' }] }
      })
    ];

    const created = await Deal.insertMany(docs);
    res.status(201).json(created.map((d) => sm.serializeDeal(d, isBrand ? 'brand' : 'creator')));
  } catch (err) {
    next(err);
  }
};

// POST /api/deals/:dealId/release  (admin force-release / retry watermark)
exports.adminRelease = async (req, res, next) => {
  try {
    if (req.user.role !== 'admin') return fail(res, 403, 'Admin access required');
    const deal = await Deal.findOne({ deal_id: req.params.dealId });
    if (!deal) return fail(res, 404, 'Deal not found');
    sm.releasePayment(deal, { actor_name: displayName(req.user) });
    sm.logEvent(deal, { actor_type: 'admin', actor_name: displayName(req.user), event_type: 'admin_release', message: 'Admin completed watermark removal and released payment.' });
    await deal.save();
    res.json(sm.serializeDeal(deal, 'admin'));
  } catch (err) {
    next(err);
  }
};
