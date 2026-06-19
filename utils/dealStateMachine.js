/**
 * Deal Room state machine (PRD Section 6.6).
 *
 * Every deal has exactly one active party and one primary action per state.
 * State strings are stored verbatim and matched by the frontend (which
 * normalises any dash to " - "), so keep these EXACT.
 */

const DEAL_STATES = [
  'Accepted - Awaiting Shipment',
  'Shipped - In Transit',
  'Delivered - Awaiting Receipt Confirmation',
  'Received - Content in Progress',
  'Content Submitted - Awaiting Review',
  'Revision Requested',
  'Approved - Payment Processing',
  'Paid - Complete'
];

const EXCEPTION_STATES = ['Disputed', 'Damaged/Wrong Product Reported'];

const S = {
  AWAITING_SHIPMENT: 'Accepted - Awaiting Shipment',
  IN_TRANSIT: 'Shipped - In Transit',
  AWAITING_RECEIPT: 'Delivered - Awaiting Receipt Confirmation',
  IN_PROGRESS: 'Received - Content in Progress',
  AWAITING_REVIEW: 'Content Submitted - Awaiting Review',
  REVISION_REQUESTED: 'Revision Requested',
  PAYMENT_PROCESSING: 'Approved - Payment Processing',
  PAID: 'Paid - Complete',
  DISPUTED: 'Disputed',
  DAMAGED: 'Damaged/Wrong Product Reported'
};

// active_party + primary action copy for each state
const STATE_CONFIG = {
  [S.AWAITING_SHIPMENT]: { active_party: 'brand', primary_next_action: 'Upload tracking ID' },
  [S.IN_TRANSIT]: { active_party: 'system', primary_next_action: 'Awaiting courier delivery' },
  [S.AWAITING_RECEIPT]: { active_party: 'creator', primary_next_action: 'Mark received + upload unboxing' },
  [S.IN_PROGRESS]: { active_party: 'creator', primary_next_action: 'Submit content' },
  [S.AWAITING_REVIEW]: { active_party: 'brand', primary_next_action: 'Review and approve / request revision' },
  [S.REVISION_REQUESTED]: { active_party: 'creator', primary_next_action: 'Submit revision' },
  [S.PAYMENT_PROCESSING]: { active_party: 'system', primary_next_action: 'Releasing payment' },
  [S.PAID]: { active_party: 'none', primary_next_action: 'Deal complete' },
  [S.DISPUTED]: { active_party: 'admin', primary_next_action: 'Awaiting admin resolution' },
  [S.DAMAGED]: { active_party: 'admin', primary_next_action: 'Awaiting admin + brand resolution' }
};

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

// Default deadline window (hours) granted to the active party on entering a state.
const STATE_DEADLINE_HOURS = {
  [S.AWAITING_SHIPMENT]: 72,
  [S.AWAITING_RECEIPT]: 48,
  [S.IN_PROGRESS]: 120,
  [S.AWAITING_REVIEW]: 120, // 5-day auto-approval window (6.6)
  [S.REVISION_REQUESTED]: 72
};

const AUTO_APPROVAL_DAYS = 5;

function isExceptionState(state) {
  return EXCEPTION_STATES.includes(state);
}

function activePartyFor(state) {
  return (STATE_CONFIG[state] || {}).active_party || 'none';
}

function primaryActionFor(state) {
  return (STATE_CONFIG[state] || {}).primary_next_action || 'Waiting';
}

/**
 * Move a deal into `nextState`, stamping the entry time, recomputing the
 * deadline, and appending an activity-feed event. Mutates `deal`.
 */
function transition(deal, nextState, { actor_type = 'system', actor_name = 'System', message, event_type = 'state_change' } = {}) {
  deal.current_state = nextState;
  deal.state_started_at = new Date();

  const hours = STATE_DEADLINE_HOURS[nextState];
  deal.next_deadline_at = hours ? new Date(Date.now() + hours * HOUR_MS) : null;

  if (message) {
    deal.activity_feed.push({ actor_type, actor_name, event_type, message, timestamp: new Date() });
  }
  return deal;
}

function logEvent(deal, { actor_type = 'system', actor_name = 'System', event_type = 'note', message }) {
  deal.activity_feed.push({ actor_type, actor_name, event_type, message, timestamp: new Date() });
}

/**
 * Apply time-based transitions that don't need an explicit action (6.6):
 *  - Auto-approval: brand silent for 5 days after submission -> Approved -> Paid.
 * Returns true if the deal was mutated (caller should save).
 */
function applyTimeouts(deal) {
  let changed = false;

  if (deal.current_state === S.AWAITING_REVIEW && deal.state_started_at) {
    const elapsed = Date.now() - new Date(deal.state_started_at).getTime();
    if (elapsed >= AUTO_APPROVAL_DAYS * DAY_MS) {
      approveContent(deal, { auto: true });
      // System releases payment per schedule (state 7 -> 8).
      releasePayment(deal, { actor_name: 'System' });
      changed = true;
    }
  }
  return changed;
}

/**
 * Approve the latest content version and queue payment (6.6 states 7 -> 8,
 * 6.9 watermark removal atomic with payment queuing).
 */
function approveContent(deal, { auto = false, actor_name = 'Brand' } = {}) {
  const latest = deal.content.versions[deal.content.versions.length - 1];
  if (latest) latest.status = 'approved';

  deal.approval.approved_at = new Date();
  deal.approval.auto_approved = auto;

  // Queue escrow release per schedule.
  const deductionTotal = (deal.escrow.deductions || []).reduce((sum, d) => sum + (d.amount || 0), 0);
  deal.escrow.net_payable = Math.max(0, (deal.escrow.held_amount || 0) - deductionTotal);
  deal.escrow.status = 'queued';
  deal.escrow.estimated_payout_at = new Date(Date.now() + 2 * DAY_MS);

  transition(deal, S.PAYMENT_PROCESSING, {
    actor_type: auto ? 'system' : 'brand',
    actor_name: auto ? 'System' : actor_name,
    event_type: 'approved',
    message: auto
      ? 'Auto-approved after 5 days with no brand review. Payment queued.'
      : 'Brand approved the content. Payment queued per the creator\'s schedule.'
  });

  // Begin watermark removal; flips to processing then released by releasePayment.
  deal.content.watermark_removal_processing = true;

  return deal;
}

/**
 * Finalise payout: remove watermark + release escrow (6.6 state 8). Used by the
 * payout job / admin. Returns the deal.
 */
function releasePayment(deal, { actor_name = 'System', watermarkFailed = false } = {}) {
  if (watermarkFailed) {
    // 6.10 watermark removal failure -> Processing state visible to both parties.
    deal.content.watermark_removal_processing = true;
    logEvent(deal, {
      actor_type: 'system',
      event_type: 'watermark_failed',
      message: 'Watermark removal failed. Deal is in Processing; admin has been alerted.'
    });
    return deal;
  }

  deal.content.watermark_required_until_approval = false;
  deal.content.watermark_removal_processing = false;
  deal.escrow.status = 'released';
  deal.escrow.released_at = new Date();

  transition(deal, S.PAID, {
    actor_type: 'system',
    actor_name,
    event_type: 'paid',
    message: `Payment of ₹${deal.escrow.net_payable} released to the creator. Deal complete.`
  });
  return deal;
}

// --- Serialisation ----------------------------------------------------------

function hoursUntil(date) {
  if (!date) return null;
  return Math.round((new Date(date).getTime() - Date.now()) / HOUR_MS);
}

/**
 * Produce the view object the frontend Deal Room expects. `viewerParty` is
 * 'brand' | 'creator' | 'admin' and controls the can_* affordance flags.
 */
function serializeDeal(deal, viewerParty = 'creator') {
  const d = typeof deal.toObject === 'function' ? deal.toObject() : deal;
  const state = d.current_state;
  const active = activePartyFor(state);
  const exception = isExceptionState(state);

  let countdown;
  if (state === S.AWAITING_REVIEW && d.state_started_at) {
    const deadline = new Date(d.state_started_at).getTime() + AUTO_APPROVAL_DAYS * DAY_MS;
    countdown = Math.max(0, Math.round((deadline - Date.now()) / HOUR_MS));
  } else {
    countdown = hoursUntil(d.next_deadline_at);
  }

  const mapEvent = (e) => ({
    id: String(e._id),
    actor_type: e.actor_type,
    actor_name: e.actor_name,
    event_type: e.event_type,
    message: e.message,
    timestamp: e.timestamp
  });

  return {
    deal_id: d.deal_id,
    current_state: state,
    state_started_at: d.state_started_at,
    active_party: active,
    viewer_party: viewerParty,
    primary_next_action: primaryActionFor(state),
    deadline: d.next_deadline_at,
    next_deadline_at: d.next_deadline_at,
    deadline_countdown_hours: countdown,

    campaign: {
      id: d.campaign_id,
      title: d.campaign_title,
      deal_id: d.deal_id,
      brand_handle: d.brand_handle,
      business_nickname: d.brand_name,
      status: state
    },
    brand: { name: d.brand_name, handle: d.brand_handle, logo_url: d.brand_logo_url },
    creator: { name: d.creator_name, handle: d.creator_handle },
    my_bid: { amount: d.bid_amount },

    brief_sections: d.brief_sections || [],
    shipment: d.shipment || {},
    receipt: d.receipt || {},

    content_submission: {
      required_assets: (d.content && d.content.required_assets) || {},
      watermark_required_until_approval: !!(d.content && d.content.watermark_required_until_approval),
      watermark_removal_processing: !!(d.content && d.content.watermark_removal_processing),
      versions: ((d.content && d.content.versions) || []).map((v) => ({
        version: v.version,
        video_url: v.video_url,
        caption_url: v.caption_url,
        thumbnail_url: v.thumbnail_url,
        raw_footage_url: v.raw_footage_url,
        creator_note: v.creator_note,
        submitted_at: v.submitted_at,
        status: v.status
      }))
    },

    revision_tracker: {
      revision_limit: (d.revision && d.revision.revision_limit) || 0,
      revision_count_used: (d.revision && d.revision.revision_count_used) || 0,
      latest_feedback: (d.revision && d.revision.latest_feedback) || null,
      requested_changes: (d.revision && d.revision.requested_changes) || [],
      new_deadline_at: (d.revision && d.revision.new_deadline_at) || null
    },

    escrow: {
      held_amount: (d.escrow && d.escrow.held_amount) || 0,
      net_payable: (d.escrow && d.escrow.net_payable) || 0,
      deductions: (d.escrow && d.escrow.deductions) || [],
      estimated_payout_at: (d.escrow && d.escrow.estimated_payout_at) || null,
      status: (d.escrow && d.escrow.status) || 'held'
    },

    dispute: d.dispute || {},
    activity_feed: (d.activity_feed || []).map(mapEvent).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
    chat_summary: {
      messages: (d.messages || []).map((m) => ({
        id: String(m._id),
        sender_type: m.sender_type,
        sender_name: m.sender_name,
        message: m.message,
        attachment_urls: m.attachment_urls || [],
        created_at: m.created_at
      }))
    },
    action_cards: (d.action_cards || []).map((c) => ({
      id: String(c._id),
      type: c.type,
      title: c.title,
      message: c.message,
      status: c.status,
      attachment_urls: c.attachment_urls || [],
      created_at: c.created_at
    })),

    // Affordance flags consumed by both Deal Rooms
    can_mark_received: viewerParty === 'creator' && state === S.AWAITING_RECEIPT && !exception,
    can_submit_content:
      viewerParty === 'creator' && (state === S.IN_PROGRESS || state === S.REVISION_REQUESTED) && !exception,
    can_upload_tracking: viewerParty === 'brand' && state === S.AWAITING_SHIPMENT && !exception,
    can_review_content: viewerParty === 'brand' && state === S.AWAITING_REVIEW && !exception,
    revisions_remaining: Math.max(
      0,
      ((d.revision && d.revision.revision_limit) || 0) - ((d.revision && d.revision.revision_count_used) || 0)
    )
  };
}

module.exports = {
  DEAL_STATES,
  EXCEPTION_STATES,
  STATES: S,
  STATE_CONFIG,
  AUTO_APPROVAL_DAYS,
  isExceptionState,
  activePartyFor,
  primaryActionFor,
  transition,
  logEvent,
  applyTimeouts,
  approveContent,
  releasePayment,
  serializeDeal
};
