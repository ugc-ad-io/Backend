const Thread = require('../models/Thread');
const Message = require('../models/Message');
const User = require('../models/User');
const Deal = require('../models/Deal');
const AdminLog = require('../models/AdminLog');
const sm = require('../utils/dealStateMachine');
const filter = require('../utils/contactFilter');
const policy = require('../utils/chatPolicy');
const notif = require('../utils/notifications');

const fail = (res, status, detail) => res.status(status).json({ detail });

const ACTION_CARDS_BY_ROLE = {
  creator: ['custom_offer', 'counter_offer', 'revision_request', 'milestone_update', 'damage_report', 'escalate_to_admin', 'raise_dispute'],
  business: ['private_invitation', 'custom_offer', 'counter_offer', 'revision_request', 'milestone_update', 'escalate_to_admin', 'raise_dispute'],
  admin: Message.ACTION_CARD_TYPES
};

const CARD_EXPIRY_HOURS = { custom_offer: 48, private_invitation: 72, counter_offer: 48 };
const NO_RESPONSE_CARDS = ['milestone_update', 'damage_report', 'escalate_to_admin', 'raise_dispute'];
// free-text fields inside cards that must be contact-filtered (10.5.5)
const FILTERED_CARD_FIELDS = ['notes', 'diff_vs_original', 'description', 'summary'];

function availableActions(type) {
  if (NO_RESPONSE_CARDS.includes(type)) return [];
  if (type === 'revision_request') return ['accept', 'flag_scope_creep', 'partial_accept'];
  return ['accept', 'counter', 'reject']; // offers + invitation
}

async function relationshipExists(aId, bId) {
  const deal = await Deal.findOne({
    $or: [
      { brand_id: aId, creator_id: bId },
      { brand_id: bId, creator_id: aId }
    ]
  });
  return !!deal;
}

/**
 * Find or create the pair thread, enforcing access gating (10.2):
 *  - existing thread => always allowed
 *  - brand initiating => wallet >= MIN_CHAT_BALANCE
 *  - creator initiating => must already have a deal/invitation relationship
 */
async function getOrCreateThread(sender, recipient) {
  const key = Thread.pairKey(sender._id, recipient._id);
  let thread = await Thread.findOne({ pair_key: key });
  if (thread) return { thread, created: false };

  if (sender.role === 'business') {
    if (sender.wallet_balance < policy.MIN_CHAT_BALANCE) {
      const e = new Error(`Add at least ₹${policy.MIN_CHAT_BALANCE.toLocaleString('en-IN')} to your wallet to start new conversations.`);
      e.statusCode = 402;
      throw e;
    }
  } else if (sender.role === 'creator') {
    if (!(await relationshipExists(sender._id, recipient._id))) {
      const e = new Error('You can only message brands that have invited you or have an active deal with you.');
      e.statusCode = 403;
      throw e;
    }
  }

  thread = await Thread.create({
    participants: [sender._id, recipient._id],
    pair_key: key,
    initiated_by: sender._id,
    unread: {}
  });
  return { thread, created: true };
}

function otherParticipant(thread, userId) {
  return thread.participants.find((p) => String(p) !== String(userId));
}

async function pushSystem(thread, message) {
  const msg = await Message.create({ thread_id: thread._id, item_type: 'system', sender_type: 'system', system_message: true, message });
  thread.last_message = { message, sender_id: null, item_type: 'system', attachment_urls: [], timestamp: msg.createdAt };
  return msg;
}

function bumpUnread(thread, recipientId) {
  const k = String(recipientId);
  thread.unread.set(k, (thread.unread.get(k) || 0) + 1);
}

function serializeMessage(msg, viewerId, includeReceipts) {
  const base = {
    id: String(msg._id),
    item_type: msg.item_type,
    sender_id: msg.sender_id ? String(msg.sender_id) : (msg.sender_type === 'admin' ? 'admin' : 'system'),
    sender_type: msg.sender_type,
    created_at: msg.createdAt,
    timestamp: msg.createdAt
  };

  if (msg.item_type === 'system') {
    return { ...base, system_message: true, message: msg.message };
  }

  if (msg.item_type === 'action_card') {
    const expired = msg.expires_at && new Date(msg.expires_at) < new Date() && msg.card_status === 'open';
    return {
      ...base,
      type: msg.type,
      fields: msg.fields || {},
      deal_id: msg.deal_id,
      status: expired ? 'expired' : msg.card_status,
      is_expired: !!expired,
      available_actions: expired || msg.card_status !== 'open' ? [] : availableActions(msg.type),
      response: msg.response
    };
  }

  // free-form
  const isOwn = String(msg.sender_id) === String(viewerId);
  let status = msg.status;
  let read_at = msg.read_at;
  let read_by = (msg.read_by || []).map(String);
  if (!includeReceipts) {
    // Read receipts disabled by a party => cap at "Delivered" for both (10.6)
    if (status === 'read') status = 'delivered';
    read_at = null;
    read_by = [];
  }
  return {
    ...base,
    message: msg.message,
    attachment_urls: msg.attachment_urls || [],
    status: isOwn ? status : msg.status,
    read_at,
    read_by
  };
}

// GET /api/chat/conversations
exports.conversations = async (req, res, next) => {
  try {
    const uid = req.user.id;
    const threads = await Thread.find({ participants: uid }).sort({ updatedAt: -1 });
    const otherIds = threads.map((t) => otherParticipant(t, uid)).filter(Boolean);
    const users = await User.find({ _id: { $in: otherIds } });
    const userMap = new Map(users.map((u) => [String(u._id), u]));

    const out = await Promise.all(
      threads.map(async (t) => {
        const otherId = otherParticipant(t, uid);
        const other = userMap.get(String(otherId));
        const archived = t.archived_by.map(String).includes(String(uid));
        const deal = await Deal.findOne({
          $or: [
            { brand_id: uid, creator_id: otherId },
            { brand_id: otherId, creator_id: uid }
          ]
        }).sort({ updatedAt: -1 });
        const activeDeal = deal && !['Paid - Complete'].includes(deal.current_state);
        const classification = archived ? 'archived' : activeDeal ? 'active_deal' : 'no_deal';

        return {
          user_id: String(otherId),
          nickname: other?.nickname || other?.full_name || 'User',
          status: classification, // legacy field used by some helpers
          thread_classification: classification,
          timestamp: t.last_message?.timestamp || t.updatedAt,
          last_message: t.last_message || {},
          unread_count: t.unread.get(String(uid)) || 0,
          associated_deal_status: deal ? deal.current_state : null,
          counterparty_active: other ? other.active : false
        };
      })
    );

    res.json(out);
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/:otherId  -> message list (marks incoming as read)
exports.getMessages = async (req, res, next) => {
  try {
    const uid = req.user.id;
    const otherId = req.params.otherId;
    const viewer = await User.findById(uid);
    const other = await User.findById(otherId);
    const thread = await Thread.findOne({ pair_key: Thread.pairKey(uid, otherId) });
    if (!thread) return res.json([]);

    // Mark the other party's messages as read by me (read receipts)
    await Message.updateMany(
      { thread_id: thread._id, sender_id: otherId, status: { $ne: 'read' } },
      { $set: { status: 'read', read_at: new Date() }, $addToSet: { read_by: uid } }
    );
    thread.unread.set(String(uid), 0);
    await thread.save();

    const includeReceipts = !!(viewer?.settings?.read_receipts && other?.settings?.read_receipts);
    const messages = await Message.find({ thread_id: thread._id }).sort({ createdAt: 1 });
    res.json(messages.map((m) => serializeMessage(m, uid, includeReceipts)));
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/warnings
exports.warnings = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(policy.warningsView(user || { chat: { strikes: [] } }));
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/:otherId/typing
exports.getTyping = async (req, res, next) => {
  try {
    const thread = await Thread.findOne({ pair_key: Thread.pairKey(req.user.id, req.params.otherId) });
    if (!thread) return res.json({ typing: false });
    const ts = thread.typing.get(String(req.params.otherId));
    const typing = ts && Date.now() - new Date(ts).getTime() < 6000;
    res.json({ typing: !!typing });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/:otherId/typing
exports.setTyping = async (req, res, next) => {
  try {
    const thread = await Thread.findOne({ pair_key: Thread.pairKey(req.user.id, req.params.otherId) });
    if (thread) {
      thread.typing.set(String(req.user.id), new Date());
      await thread.save();
    }
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};

async function notifyAdminsOfStrike(user, strike) {
  if (!strike.notify_admin) return;
  const admins = await User.find({ role: 'admin' });
  await Promise.all(
    admins.map((a) =>
      notif.notify({
        user: a,
        type: 'filter_strike',
        title: 'Contact-info filter strike',
        body: `${user.nickname || user.email} hit strike ${strike.warning_count} (${strike.action}).`,
        critical: true
      })
    )
  );
}

// POST /api/chat/send { recipient_id, message, attachment_urls }
exports.send = async (req, res, next) => {
  try {
    const { recipient_id, message, attachment_urls = [] } = req.body;
    if (!recipient_id) return fail(res, 400, 'recipient_id is required');

    const sender = await User.findById(req.user.id);
    const recipient = await User.findById(recipient_id);
    if (!recipient) return fail(res, 404, 'Recipient not found');
    if (!recipient.active) return fail(res, 409, 'This user is no longer active on UGCAD.IO.');

    if (policy.isSuspended(sender)) return fail(res, 403, 'Your chat access is suspended pending admin review.');
    if (policy.isPaused(sender)) return fail(res, 429, 'Your chat is temporarily paused. Please try again shortly.');
    if (policy.isActionCardsOnly(sender)) return fail(res, 403, 'Free-form chat is disabled on your account. You can still use Action Cards.');

    let thread;
    try {
      ({ thread } = await getOrCreateThread(sender, recipient));
    } catch (e) {
      return fail(res, e.statusCode || 403, e.message);
    }

    const realText = String(message || '').startsWith('__UGCAD_ATTACHMENT__:') ? '' : message;

    // Contact-info filter on text (10.4)
    const textResult = filter.check(realText);
    // OCR-scan image attachments (10.4 image filtering)
    let imageResult = { hasContact: false, matches: [] };
    for (const url of attachment_urls) {
      if (/\.(png|jpe?g|gif|webp)$/i.test(String(url).split('?')[0])) {
        const r = await filter.scanImage({ url });
        if (r.hasContact) { imageResult = r; break; }
      }
    }

    if (textResult.hasContact || imageResult.hasContact) {
      const matched = [...textResult.matches, ...imageResult.matches];
      const strike = policy.recordStrike(sender, {
        category: imageResult.hasContact ? 'image' : 'contact_info',
        thread_id: thread._id,
        matched,
        snippet: realText.slice(0, 140)
      });
      await sender.save();
      await notifyAdminsOfStrike(sender, strike);
      return res.status(400).json({
        detail: policy.BLOCK_MESSAGE,
        filtered: true,
        warning_issued: true,
        warning_count: strike.warning_count,
        warning_action: strike.action
      });
    }

    const msg = await Message.create({
      thread_id: thread._id,
      item_type: 'message',
      sender_id: sender._id,
      recipient_id: recipient._id,
      message: message || '',
      attachment_urls,
      status: 'delivered'
    });
    thread.last_message = {
      message: realText || (attachment_urls.length ? 'File attachment' : ''),
      sender_id: sender._id,
      item_type: 'message',
      attachment_urls,
      timestamp: msg.createdAt
    };
    bumpUnread(thread, recipient._id);
    thread.typing.set(String(sender._id), new Date(0));
    await thread.save();

    const includeReceipts = !!(sender.settings?.read_receipts && recipient.settings?.read_receipts);
    res.status(201).json({ ...serializeMessage(msg, sender._id, includeReceipts), filtered: false });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/action-cards { recipient_id, type, fields }
exports.createActionCard = async (req, res, next) => {
  try {
    const { recipient_id, type, fields = {} } = req.body;
    if (!recipient_id || !type) return fail(res, 400, 'recipient_id and type are required');
    if (!Message.ACTION_CARD_TYPES.includes(type)) return fail(res, 400, 'Unknown action card type');

    const sender = await User.findById(req.user.id);
    const recipient = await User.findById(recipient_id);
    if (!recipient) return fail(res, 404, 'Recipient not found');
    if (!recipient.active) return fail(res, 409, 'This user is no longer active on UGCAD.IO.');
    if (policy.isSuspended(sender)) return fail(res, 403, 'Your chat access is suspended pending admin review.');

    const allowed = ACTION_CARDS_BY_ROLE[sender.role] || [];
    if (!allowed.includes(type)) return fail(res, 403, `Your role cannot send a ${type.replace(/_/g, ' ')}.`);

    // Deal-bound cards only make sense against a LIVE deal in the right state.
    // Without this, a brand could send a "Revision Request" on a Paid - Complete
    // deal (the money's already released), or a milestone update with no deal at
    // all — both of which are meaningless and confusing to the other side.
    if (['revision_request', 'milestone_update'].includes(type)) {
      const deal = await Deal.findOne({
        $or: [
          { brand_id: sender._id, creator_id: recipient._id },
          { brand_id: recipient._id, creator_id: sender._id },
        ],
      }).sort({ updatedAt: -1 });

      if (!deal) return fail(res, 409, 'There is no active deal with this user yet.');
      const state = deal.current_state;
      const done = state === sm.STATES.PAID;

      if (type === 'revision_request') {
        // A revision can only be asked for while the brand is reviewing submitted
        // content. Once it's approved/paid, revisions go through a new deal.
        if (done) return fail(res, 409, 'This deal is already complete — you can’t request a revision. Start a new deal for more work.');
        if (state !== sm.STATES.AWAITING_REVIEW && state !== sm.STATES.REVISION_REQUESTED) {
          return fail(res, 409, 'You can only request a revision after the creator submits content for review.');
        }
      } else if (type === 'milestone_update') {
        // No point posting milestones on a wrapped-up deal.
        if (done) return fail(res, 409, 'This deal is already complete.');
      }
    }

    let thread;
    try {
      ({ thread } = await getOrCreateThread(sender, recipient));
    } catch (e) {
      return fail(res, e.statusCode || 403, e.message);
    }

    // Contact-filter free-text fields inside the card (10.5.5)
    const combined = FILTERED_CARD_FIELDS.map((f) => fields[f]).filter(Boolean).join(' ');
    if (combined) {
      const r = filter.check(combined);
      if (r.hasContact) {
        const strike = policy.recordStrike(sender, { thread_id: thread._id, matched: r.matches, snippet: combined.slice(0, 140) });
        await sender.save();
        await notifyAdminsOfStrike(sender, strike);
        return res.status(400).json({ detail: policy.BLOCK_MESSAGE, filtered: true, warning_count: strike.warning_count });
      }
    }

    // Counter-offer 3-round cap (10.5.3)
    if (type === 'counter_offer') {
      const rounds = await Message.countDocuments({ thread_id: thread._id, type: 'counter_offer' });
      if (rounds >= 3) return fail(res, 409, 'Maximum of 3 counter rounds reached. Please accept or decline.');
    }

    const hours = CARD_EXPIRY_HOURS[type];
    const card = await Message.create({
      thread_id: thread._id,
      item_type: 'action_card',
      sender_id: sender._id,
      recipient_id: recipient._id,
      type,
      fields,
      deal_id: fields.deal_id || null,
      card_status: 'open',
      expires_at: hours ? new Date(Date.now() + hours * 3600 * 1000) : null,
      counter_round: type === 'counter_offer' ? await Message.countDocuments({ thread_id: thread._id, type: 'counter_offer' }) + 1 : 0
    });

    thread.last_message = { message: `[${type.replace(/_/g, ' ')}]`, sender_id: sender._id, item_type: 'action_card', attachment_urls: [], timestamp: card.createdAt };
    bumpUnread(thread, recipient._id);
    await thread.save();

    // Side effects on creation
    if (type === 'damage_report') {
      await pushSystem(thread, 'Damage report submitted. Admin has been notified and will review.');
      const admins = await User.find({ role: 'admin' });
      await Promise.all(admins.map((a) => notif.notify({ user: a, type: 'damage_report', title: 'Damage report', body: `${sender.nickname} filed a damage report.`, critical: true })));
    } else if (type === 'escalate_to_admin') {
      await pushSystem(thread, 'Escalated to admin. An admin will join within 24 hours to mediate.');
    } else if (type === 'raise_dispute') {
      await pushSystem(thread, 'Dispute raised. Other actions are paused pending resolution.');
      const admins = await User.find({ role: 'admin' });
      await Promise.all(admins.map((a) => notif.notify({ user: a, type: 'dispute', title: 'Dispute raised', body: `${sender.nickname} raised a dispute.`, critical: true })));
    }
    await thread.save();

    await notif.notifyActionCard({ user: recipient, cardType: type, fromName: sender.nickname || 'A user' });

    const includeReceipts = !!(sender.settings?.read_receipts && recipient.settings?.read_receipts);
    res.status(201).json(serializeMessage(card, sender._id, includeReceipts));
  } catch (err) {
    next(err);
  }
};

// Amounts come from free-text card fields (e.g. "Rs. 2,222", "₹5000") so strip
// everything that isn't a digit before Number() — otherwise currency symbols,
// thousands commas, and the "." in "Rs." produce NaN or wrong values like 0.2222.
// Budgets on this platform are whole rupees, so digit-only parsing is correct.
function parseAmount(...vals) {
  for (const v of vals) {
    if (v === undefined || v === null || v === '') continue;
    const digits = String(v).replace(/[^0-9]/g, '');
    if (digits) {
      const n = Number(digits);
      if (Number.isFinite(n) && n > 0) return n;
    }
  }
  return 0;
}

async function createDealFromCard(card, sender, responder) {
  // sender = card creator, responder = acceptor
  let brand, creator, amount;
  if (card.type === 'private_invitation') {
    brand = sender; creator = responder; amount = parseAmount(card.fields.budget);
  } else {
    // custom_offer / counter_offer originate from creator (or whoever); brand is the business party
    brand = sender.role === 'business' ? sender : responder;
    creator = sender.role === 'business' ? responder : sender;
    amount = parseAmount(card.fields.price, card.fields.modified_price, card.fields.budget);
  }

  const deal_id = `UGC-${Date.now().toString().slice(-7)}`;
  const deal = await Deal.create({
    deal_id,
    campaign_title: card.fields.campaign_name || card.fields.deliverable_type || 'Custom deal',
    brand_id: brand._id,
    brand_name: brand.nickname || brand.full_name || 'Brand',
    brand_handle: brand.nickname || 'brand',
    creator_id: creator._id,
    creator_name: creator.nickname || creator.full_name || 'Creator',
    creator_handle: creator.nickname || 'creator',
    current_state: sm.STATES.AWAITING_SHIPMENT,
    state_started_at: new Date(),
    next_deadline_at: new Date(Date.now() + 72 * 3600 * 1000),
    bid_amount: amount,
    brief_sections: [
      { title: 'Deliverable', content: String(card.fields.deliverable_summary || card.fields.deliverable_type || 'As agreed in chat') },
      { title: 'Usage Rights', content: String(card.fields.usage_rights || 'As agreed') },
      { title: 'Timeline', content: String(card.fields.timeline || 'As agreed') }
    ],
    escrow: { held_amount: amount, net_payable: amount, status: 'held' },
    activity_feed: [{ actor_type: 'system', actor_name: 'System', event_type: 'accepted', message: `Deal created from accepted ${card.type.replace(/_/g, ' ')}.`, timestamp: new Date() }]
  });
  return deal;
}

// POST /api/chat/action-cards/:cardId/respond { action, decline_reason, note }
exports.respondActionCard = async (req, res, next) => {
  try {
    const { action, decline_reason, note } = req.body;
    const card = await Message.findById(req.params.cardId);
    if (!card || card.item_type !== 'action_card') return fail(res, 404, 'Action card not found');
    if (String(card.recipient_id) !== String(req.user.id)) return fail(res, 403, 'Only the recipient can respond to this card.');
    if (card.card_status !== 'open') return fail(res, 409, `This card is already ${card.card_status}.`);
    if (card.expires_at && new Date(card.expires_at) < new Date()) {
      card.card_status = 'expired';
      await card.save();
      return fail(res, 409, 'This action card has expired.');
    }
    if (!availableActions(card.type).includes(action)) return fail(res, 400, `Invalid action "${action}" for this card.`);

    const responder = await User.findById(req.user.id);
    const sender = await User.findById(card.sender_id);
    const thread = await Thread.findById(card.thread_id);

    card.response = { action, decline_reason: decline_reason || null, note: note || null, responded_at: new Date() };

    let systemText = '';
    if (action === 'accept') {
      card.card_status = 'accepted';
      if (card.type === 'private_invitation') {
        // No deal yet — the brand posts the full brief next, which creates the deal.
        systemText = `${responder.nickname} accepted the private invitation. ${sender?.nickname || 'The brand'} can now post the brief to start the deal.`;
      } else if (['custom_offer', 'counter_offer'].includes(card.type)) {
        const deal = await createDealFromCard(card, sender, responder);
        card.deal_id = deal.deal_id;
        systemText = `${responder.nickname} accepted the ${card.type.replace(/_/g, ' ')}. Deal ${deal.deal_id} created.`;
      } else {
        systemText = `${responder.nickname} accepted the ${card.type.replace(/_/g, ' ')}.`;
      }
    } else if (action === 'reject') {
      card.card_status = 'rejected';
      systemText = `${responder.nickname} declined the ${card.type.replace(/_/g, ' ')}${decline_reason ? ` (${decline_reason})` : ''}.`;
    } else if (action === 'counter') {
      card.card_status = 'countered';
      systemText = `${responder.nickname} countered. Send a Counter Offer card with the new terms.`;
    } else if (action === 'flag_scope_creep') {
      card.card_status = 'rejected';
      systemText = `${responder.nickname} flagged the revision request as scope creep. Escalated to admin.`;
      const admins = await User.find({ role: 'admin' });
      await Promise.all(admins.map((a) => notif.notify({ user: a, type: 'scope_creep', title: 'Scope creep flagged', body: `${responder.nickname} flagged a revision request.`, critical: false })));
    } else if (action === 'partial_accept') {
      card.card_status = 'partial';
      systemText = `${responder.nickname} partially accepted the revision request.`;
    }

    await card.save();
    if (thread && systemText) {
      await pushSystem(thread, systemText);
      await thread.save();
    }
    if (sender) await notif.notify({ user: sender, type: `card_response:${action}`, title: 'Action card update', body: systemText });

    res.json({ ok: true, status: card.card_status, deal_id: card.deal_id });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/report { reported_user_id, reason }
exports.reportUser = async (req, res, next) => {
  try {
    const { reported_user_id, reason } = req.body;
    if (!reported_user_id) return fail(res, 400, 'reported_user_id is required');
    await AdminLog.create({
      admin_id: null,
      action: 'report_user',
      target_user_id: reported_user_id,
      detail: reason || 'No reason provided',
      meta: { reporter_id: req.user.id }
    });
    const admins = await User.find({ role: 'admin' });
    await Promise.all(admins.map((a) => notif.notify({ user: a, type: 'user_report', title: 'User reported', body: reason || 'A user was reported.', critical: true })));
    res.status(201).json({ ok: true, message: 'Report submitted to admin.' });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/:otherId/false-positive { strike_id }  — flag a filter false positive (10.4)
exports.flagFalsePositive = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    const { strike_id } = req.body;
    const strike = user.chat.strikes.id(strike_id) || user.chat.strikes[user.chat.strikes.length - 1];
    if (!strike) return fail(res, 404, 'No strike to review');
    strike.false_positive = true; // restores the strike on escalation to admin
    await user.save();
    const admins = await User.find({ role: 'admin' });
    await Promise.all(admins.map((a) => notif.notify({ user: a, type: 'false_positive', title: 'False-positive review', body: `${user.nickname} contests a filter strike.`, critical: false })));
    res.json({ ok: true, warning_count: policy.recentStrikeCount(user) });
  } catch (err) {
    next(err);
  }
};

module.exports.ACTION_CARDS_BY_ROLE = ACTION_CARDS_BY_ROLE;
