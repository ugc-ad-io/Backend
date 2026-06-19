const Thread = require('../models/Thread');
const Message = require('../models/Message');
const User = require('../models/User');
const AdminLog = require('../models/AdminLog');
const notif = require('../utils/notifications');

const fail = (res, status, detail) => res.status(status).json({ detail });

async function log(req, action, extra = {}) {
  return AdminLog.create({ admin_id: req.user.id, action, ...extra });
}

// GET /api/chat/admin/threads
exports.listThreads = async (req, res, next) => {
  try {
    const threads = await Thread.find({}).sort({ updatedAt: -1 }).limit(200);
    const ids = [...new Set(threads.flatMap((t) => t.participants.map(String)))];
    const users = await User.find({ _id: { $in: ids } });
    const map = new Map(users.map((u) => [String(u._id), u]));
    res.json(
      threads.map((t) => ({
        thread_id: String(t._id),
        participants: t.participants.map((p) => {
          const u = map.get(String(p));
          return { id: String(p), nickname: u?.nickname || 'User', role: u?.role, active: u?.active };
        }),
        last_message: t.last_message,
        admin_joined: t.admin_joined,
        updated_at: t.updatedAt
      }))
    );
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/admin/threads/:threadId
exports.viewThread = async (req, res, next) => {
  try {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return fail(res, 404, 'Thread not found');
    const messages = await Message.find({ thread_id: thread._id }).sort({ createdAt: 1 });
    const users = await User.find({ _id: { $in: thread.participants } });
    res.json({
      thread_id: String(thread._id),
      participants: users.map((u) => u.toPublic()),
      admin_joined: thread.admin_joined,
      messages: messages.map((m) => ({
        id: String(m._id),
        item_type: m.item_type,
        sender_id: m.sender_id ? String(m.sender_id) : (m.sender_type === 'admin' ? 'admin' : 'system'),
        sender_type: m.sender_type,
        message: m.message,
        type: m.type,
        fields: m.fields,
        card_status: m.card_status,
        attachment_urls: m.attachment_urls,
        created_at: m.createdAt
      }))
    });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/admin/threads/:threadId/join
exports.joinThread = async (req, res, next) => {
  try {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return fail(res, 404, 'Thread not found');
    thread.admin_joined = true;
    const msg = await Message.create({
      thread_id: thread._id,
      item_type: 'system',
      sender_type: 'system',
      system_message: true,
      message: 'UGCAD.IO Admin has joined this conversation.'
    });
    thread.last_message = { message: msg.message, sender_id: null, item_type: 'system', attachment_urls: [], timestamp: msg.createdAt };
    await thread.save();
    await log(req, 'join_thread', { target_thread_id: thread._id });
    const parts = await User.find({ _id: { $in: thread.participants } });
    await Promise.all(parts.map((u) => notif.notify({ user: u, type: 'admin_joined', title: 'Admin joined', body: 'UGCAD.IO Admin has joined your conversation.', critical: true })));
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/admin/threads/:threadId/message { message }
exports.postMessage = async (req, res, next) => {
  try {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return fail(res, 404, 'Thread not found');
    const { message } = req.body;
    if (!message) return fail(res, 400, 'Message is required');
    const msg = await Message.create({
      thread_id: thread._id,
      item_type: 'message',
      sender_id: req.user.id,
      sender_type: 'admin',
      message,
      status: 'delivered'
    });
    thread.last_message = { message, sender_id: req.user.id, item_type: 'message', attachment_urls: [], timestamp: msg.createdAt };
    thread.participants.forEach((p) => thread.unread.set(String(p), (thread.unread.get(String(p)) || 0) + 1));
    await thread.save();
    await log(req, 'post_message', { target_thread_id: thread._id, detail: message.slice(0, 140) });
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/admin/users/:userId/pause { hours }
exports.pauseUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return fail(res, 404, 'User not found');
    const hours = Number(req.body.hours) || 24;
    user.chat.chat_paused_until = new Date(Date.now() + hours * 3600 * 1000);
    await user.save();
    await log(req, 'pause_user', { target_user_id: user._id, detail: `${hours}h pause` });
    res.json({ ok: true, chat_paused_until: user.chat.chat_paused_until });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/admin/users/:userId/downgrade { days }
exports.downgradeUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return fail(res, 404, 'User not found');
    const days = Number(req.body.days) || 14;
    user.chat.action_cards_only_until = new Date(Date.now() + days * 24 * 3600 * 1000);
    await user.save();
    await log(req, 'downgrade_user', { target_user_id: user._id, detail: `${days}d action-cards-only` });
    res.json({ ok: true, action_cards_only_until: user.chat.action_cards_only_until });
  } catch (err) {
    next(err);
  }
};

// POST /api/chat/admin/users/:userId/restore  — lift pause/downgrade/suspension
exports.restoreUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return fail(res, 404, 'User not found');
    user.chat.chat_paused_until = null;
    user.chat.action_cards_only_until = null;
    user.chat.suspended = false;
    await user.save();
    await log(req, 'restore_user', { target_user_id: user._id });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/admin/threads/:threadId/export  -> plain-text transcript
exports.exportTranscript = async (req, res, next) => {
  try {
    const thread = await Thread.findById(req.params.threadId);
    if (!thread) return fail(res, 404, 'Thread not found');
    const messages = await Message.find({ thread_id: thread._id }).sort({ createdAt: 1 });
    const users = await User.find({ _id: { $in: thread.participants } });
    const nameOf = (id) => users.find((u) => String(u._id) === String(id))?.nickname || (id ? String(id) : 'System');
    const lines = messages.map((m) => {
      const who = m.sender_type === 'admin' ? 'ADMIN' : m.item_type === 'system' ? 'SYSTEM' : nameOf(m.sender_id);
      const ts = new Date(m.createdAt).toISOString();
      const body = m.item_type === 'action_card' ? `[${m.type}] ${JSON.stringify(m.fields)} (${m.card_status})` : m.message;
      return `[${ts}] ${who}: ${body}`;
    });
    await log(req, 'export_transcript', { target_thread_id: thread._id });
    res.json({ thread_id: String(thread._id), transcript: lines.join('\n'), count: lines.length });
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/admin/filter-log  — all contact-filter strikes (10.8)
exports.filterLog = async (req, res, next) => {
  try {
    const users = await User.find({ 'chat.strikes.0': { $exists: true } });
    const entries = [];
    users.forEach((u) => {
      (u.chat.strikes || []).forEach((s) => {
        entries.push({
          user_id: String(u._id),
          nickname: u.nickname,
          role: u.role,
          at: s.at,
          category: s.category,
          matched: s.matched,
          snippet: s.snippet,
          false_positive: s.false_positive
        });
      });
    });
    entries.sort((a, b) => new Date(b.at) - new Date(a.at));
    res.json(entries);
  } catch (err) {
    next(err);
  }
};

// GET /api/chat/admin/audit  — admin action log
exports.auditLog = async (req, res, next) => {
  try {
    const logs = await AdminLog.find({}).sort({ createdAt: -1 }).limit(300).populate('admin_id', 'nickname email');
    res.json(logs);
  } catch (err) {
    next(err);
  }
};
