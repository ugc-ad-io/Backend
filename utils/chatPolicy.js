/**
 * Chat policy engine — 3-strike escalation (PRD 10.4) and free-form gating.
 *
 * Strikes are counted per user over a rolling 30-day window. Escalation:
 *   1st  -> warning, message blocked
 *   2nd  -> stronger warning + 1-hour chat pause + admin notified
 *   3rd  -> Action-Cards-Only mode for 14 days
 *   4th+ -> account chat suspended pending admin review
 */

const STRIKE_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

// Minimum brand wallet balance required to unlock chat initiation (PRD 10.2).
const MIN_CHAT_BALANCE = 2500;

function recentStrikeCount(user) {
  const since = Date.now() - STRIKE_WINDOW_MS;
  return (user.chat?.strikes || []).filter((s) => !s.false_positive && new Date(s.at).getTime() >= since).length;
}

/**
 * Record a detected attempt and apply escalation. Mutates `user` (caller saves).
 * Returns a summary used for the response + admin notification.
 */
function recordStrike(user, { category = 'contact_info', thread_id = null, matched = [], snippet = null, accelerated = false } = {}) {
  if (!user.chat) user.chat = { strikes: [] };
  user.chat.strikes.push({ at: new Date(), category, thread_id, matched, snippet, false_positive: false });

  let count = recentStrikeCount(user);
  // Filter-evasion: persistent obfuscation jumps straight from 1st strike to downgrade (10.9).
  if (accelerated && count < 3) count = 3;

  const result = { warning_count: count, action: 'warning', notify_admin: false };

  if (count >= 4) {
    user.chat.suspended = true;
    result.action = 'suspended';
    result.notify_admin = true;
  } else if (count === 3) {
    user.chat.action_cards_only_until = new Date(Date.now() + 14 * DAY_MS);
    result.action = 'action_cards_only';
    result.notify_admin = true;
  } else if (count === 2) {
    user.chat.chat_paused_until = new Date(Date.now() + HOUR_MS);
    result.action = 'chat_paused';
    result.notify_admin = true;
  }
  return result;
}

const BLOCK_MESSAGE =
  'Your message appears to contain contact information. This cannot be shared on UGCAD.IO to protect both parties.';

function isSuspended(user) {
  return !!user.chat?.suspended;
}

function isPaused(user) {
  return !!(user.chat?.chat_paused_until && new Date(user.chat.chat_paused_until) > new Date());
}

function isActionCardsOnly(user) {
  return !!(user.chat?.action_cards_only_until && new Date(user.chat.action_cards_only_until) > new Date());
}

// Free-form chat blocked if suspended, paused, or in action-cards-only mode.
function freeFormBlocked(user) {
  return isSuspended(user) || isPaused(user) || isActionCardsOnly(user);
}

function warningsView(user) {
  return {
    warning_count: recentStrikeCount(user),
    action_cards_only_until: user.chat?.action_cards_only_until || null,
    chat_paused_until: user.chat?.chat_paused_until || null,
    suspended: !!user.chat?.suspended
  };
}

module.exports = {
  MIN_CHAT_BALANCE,
  BLOCK_MESSAGE,
  recentStrikeCount,
  recordStrike,
  isSuspended,
  isPaused,
  isActionCardsOnly,
  freeFormBlocked,
  warningsView
};
