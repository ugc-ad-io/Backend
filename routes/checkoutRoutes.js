// Brand checkout — "Proceed to payment" on a brief.
//
// The brand's wallet is a prepaid balance. Booking a creator SPENDS it: the money
// leaves the wallet and is held in the deal's escrow until the brand approves the
// content. Before this existed, checkout created the campaign and marked escrow
// "held" without touching the wallet at all — it just said "Brief sent" and charged
// nobody. That is the bug this file closes.
//
// Nothing here trusts a price sent by the browser. Every figure is recomputed from
// the creator's rate card and the admin's commission setting.
const express = require('express');
const mongoose = require('mongoose');
const { auth } = require('../middleware/auth');
const User = require('../models/User');
const Campaign = require('../models/Campaign');
const { ensureDealForCampaign } = require('../utils/ensureDeal');
const pricing = require('../services/pricing');

const router = express.Router();
const fail = (res, status, body) => res.status(status).json(body);

// Price a brief and report whether the wallet can cover it, so the checkout screen
// shows figures the server actually agrees with.
router.get('/quote', auth, async (req, res) => {
  try {
    const creator = await User.findById(req.query.creator_id).lean();
    if (!creator) return fail(res, 404, { detail: 'Creator not found' });
    const feePercent = await pricing.platformFeePercent();
    const q = pricing.quote(creator, req.query.video_count, feePercent);
    const brand = await User.findById(req.user.id).lean();
    const balance = (brand && brand.wallet_balance) || 0;
    res.json({
      ...q,
      wallet_balance: balance,
      sufficient: balance >= q.total,
      shortfall: Math.max(0, q.total - balance),
    });
  } catch (e) {
    return fail(res, e.status || 500, { detail: e.message });
  }
});

// POST /api/checkout/brief  { creator_id, video_count, brief }
// Debit the wallet, then start the campaign + deal with the money in escrow.
router.post('/brief', auth, async (req, res) => {
  try {
    if (req.user.role !== 'business') return fail(res, 403, { detail: 'Only brands can book a creator.' });

    const { creator_id, video_count, brief } = req.body;
    if (!creator_id || !mongoose.isValidObjectId(String(creator_id))) {
      return fail(res, 400, { detail: 'A creator must be selected.' });
    }
    const creator = await User.findById(creator_id).lean();
    if (!creator || creator.role !== 'creator') return fail(res, 404, { detail: 'Creator not found' });
    if (creator.approval_status !== 'approved') return fail(res, 400, { detail: 'This creator is not accepting briefs yet.' });

    const feePercent = await pricing.platformFeePercent();
    const q = pricing.quote(creator, video_count, feePercent); // throws 400 if the creator has no rate

    // Debit and balance-check in ONE atomic update. Doing `find` then `save` would
    // let two concurrent bookings both pass the check and overdraw the wallet.
    const brand = await User.findOneAndUpdate(
      { _id: req.user.id, wallet_balance: { $gte: q.total } },
      { $inc: { wallet_balance: -q.total } },
      { new: true }
    );

    if (!brand) {
      // The only reason the update matched nothing: not enough balance.
      const current = await User.findById(req.user.id).lean();
      const balance = (current && current.wallet_balance) || 0;
      return fail(res, 402, {
        detail: `Not enough credits. This brief costs ₹${q.total.toLocaleString('en-IN')} but your wallet has ₹${balance.toLocaleString('en-IN')}.`,
        code: 'INSUFFICIENT_FUNDS',
        required: q.total,
        available: balance,
        shortfall: q.total - balance,
      });
    }

    // Money is out of the wallet. From here on, any failure must put it back.
    let campaign;
    try {
      campaign = await Campaign.create({
        ...(brief || {}),
        business_id: String(req.user.id),
        selected_creator: String(creator_id),
        // Paid for up front, so it starts immediately — no admin approval gate.
        status: 'in_progress',
        // The creator's take. The platform fee is charged on top and is NOT escrowed.
        budget_min: q.subtotal,
        budget_max: q.subtotal,
        escrow_amount: q.subtotal,
        platform_fee: q.fee,
        fee_percent: q.fee_percent,
        amount_paid: q.total,
        paid_at: new Date(),
        video_count: q.video_count,
      });
    } catch (e) {
      await User.findByIdAndUpdate(req.user.id, { $inc: { wallet_balance: q.total } });
      throw e;
    }

    let deal = null;
    try {
      deal = await ensureDealForCampaign(campaign, String(creator_id), String(req.user.id));
    } catch (e) {
      // Refund and undo — a campaign with no Deal Room and no escrow is worse than
      // no campaign at all, and the brand is owed their money back.
      await User.findByIdAndUpdate(req.user.id, { $inc: { wallet_balance: q.total } });
      await Campaign.findByIdAndDelete(campaign._id);
      throw e;
    }

    res.status(201).json({
      success: true,
      campaign_id: String(campaign._id),
      deal_id: deal.deal_id,
      amount_charged: q.total,
      subtotal: q.subtotal,
      fee: q.fee,
      fee_percent: q.fee_percent,
      wallet_balance: brand.wallet_balance,
    });
  } catch (e) {
    return fail(res, e.status || 500, { detail: e.message || 'Checkout failed.' });
  }
});

module.exports = router;
