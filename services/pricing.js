// Single source of truth for what a brand pays.
//
// The brand is quoted `subtotal + platform fee`. The subtotal is the creator's
// own rate (they receive it in full); the fee is the platform's cut, charged on
// top. Never trust an amount sent by the client — every figure here is derived
// server-side from the creator's rate card and the admin's commission setting.
const mongoose = require('mongoose');

const DEFAULT_FEE_PERCENT = 20;
const MAX_VIDEOS = 10;

// Read the admin's commission_rate straight off the collection. We deliberately
// don't register a Settings model here: server.js owns that schema, and defining
// a second, thinner one would win the `mongoose.models.Settings ||` race and drop
// every other settings field.
async function platformFeePercent() {
  try {
    const s = await mongoose.connection.db.collection('settings').findOne({ key: 'platform' });
    const rate = Number(s && s.commission_rate);
    if (Number.isFinite(rate) && rate >= 0 && rate <= 100) return rate;
  } catch (e) { /* fall through to the default */ }
  return DEFAULT_FEE_PERCENT;
}

// A creator's per-video rate, off their rate card. Stored as free text
// ("Rs. 8,000", "8000/video"), so keep the digits and nothing else.
function creatorRate(creator) {
  const rc = ((creator && creator.profile) || {}).rate_card || {};
  const raw = String(rc.expected_payout || rc.last_salary || '');
  const digits = raw.replace(/[^0-9]/g, '');
  return parseInt(digits, 10) || 0;
}

// The authoritative quote for a brief. Throws with a user-facing message when the
// brief can't be priced, so the caller can surface it as a 400 rather than
// silently charging ₹0.
function quote(creator, videoCount, feePercent) {
  const count = Math.max(1, Math.min(MAX_VIDEOS, parseInt(videoCount, 10) || 1));
  const rate = creatorRate(creator);
  if (!rate) {
    const err = new Error("This creator hasn't set their rate yet, so the brief can't be priced.");
    err.status = 400;
    throw err;
  }
  const subtotal = rate * count;
  const fee = Math.round(subtotal * (feePercent / 100));
  return {
    rate,
    video_count: count,
    subtotal,
    fee_percent: feePercent,
    fee,
    total: subtotal + fee,
    currency: 'INR',
  };
}

module.exports = { platformFeePercent, creatorRate, quote, DEFAULT_FEE_PERCENT, MAX_VIDEOS };
