const Notification = require('../models/Notification');

/**
 * Notification service (PRD 10.7). Quiet hours (10 PM–8 AM, user timezone)
 * suppress non-critical push/email; SLA-critical events override quiet hours.
 *
 * Channels here are persisted as in-app/queued records — a real deployment wires
 * an email/SMS/WhatsApp provider at the send() call. Action Cards (offers,
 * invitations, revisions, damage) and admin interventions are sent instantly.
 */

const INSTANT_CARD_TYPES = ['private_invitation', 'custom_offer', 'revision_request', 'damage_report'];

function hourInTimezone(timezone = 'Asia/Kolkata') {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric',
      hour12: false
    }).formatToParts(new Date());
    const hourPart = parts.find((p) => p.type === 'hour');
    return Number(hourPart?.value ?? 9);
  } catch {
    return new Date().getHours();
  }
}

function isQuietHours(timezone) {
  const h = hourInTimezone(timezone);
  return h >= 22 || h < 8;
}

/**
 * Create a notification respecting prefs + quiet hours. Returns the record.
 */
async function notify({ user, type, title = '', body = '', channel = 'in_app', critical = false }) {
  if (!user) return null;

  const prefs = user.settings?.notifications || {};
  if (channel === 'email' && prefs.email === false && !critical) return null;
  if (channel === 'sms' && prefs.sms === false && !critical) return null;
  if (channel === 'whatsapp' && prefs.whatsapp === false && !critical) return null;

  let deferred_until = null;
  if (!critical && channel !== 'in_app' && isQuietHours(user.settings?.timezone)) {
    // Hold until 8 AM local — approximate next-morning delivery.
    const d = new Date();
    d.setHours(8, 0, 0, 0);
    if (d <= new Date()) d.setDate(d.getDate() + 1);
    deferred_until = d;
  }

  return Notification.create({
    user_id: user._id,
    type,
    channel,
    title,
    body,
    critical,
    deferred_until
  });
}

/** Notify a user that an Action Card arrived, choosing instant vs digest. */
async function notifyActionCard({ user, cardType, fromName }) {
  const instant = INSTANT_CARD_TYPES.includes(cardType);
  await notify({
    user,
    type: `action_card:${cardType}`,
    title: `New ${cardType.replace(/_/g, ' ')}`,
    body: `${fromName} sent you a ${cardType.replace(/_/g, ' ')}.`,
    channel: instant ? 'email' : 'in_app',
    critical: cardType === 'damage_report'
  });
}

module.exports = { notify, notifyActionCard, isQuietHours, INSTANT_CARD_TYPES };
