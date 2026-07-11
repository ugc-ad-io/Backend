// Brand checkout: quote → Razorpay order → signed verification → fulfilment.
//
// The rule this file enforces: a Campaign and its Deal (with escrow marked held)
// may only come into existence AFTER Razorpay tells us, with a signature we can
// verify, that the brand's money actually moved. Before this existed the checkout
// created the deal outright and told the brand "Brief sent" without charging them.
const express = require('express');
const mongoose = require('mongoose');
const { auth } = require('../middleware/auth');
const User = require('../models/User');
const Campaign = require('../models/Campaign');
const PaymentOrder = require('../models/PaymentOrder');
const { ensureDealForCampaign } = require('../utils/ensureDeal');
const pricing = require('../services/pricing');
const rzp = require('../services/razorpayService');

const router = express.Router();

const fail = (res, status, detail) => res.status(status).json({ detail });

// What the browser needs to open Razorpay's widget. The key id is public; the
// secret never leaves the server.
router.get('/config', auth, (req, res) => {
  res.json({ enabled: rzp.isConfigured(), key_id: rzp.publicKeyId() });
});

// Price a brief without committing to anything — lets the checkout screen show
// figures the server actually agrees with, instead of computing its own.
router.get('/quote', auth, async (req, res) => {
  try {
    const creator = await User.findById(req.query.creator_id).lean();
    if (!creator) return fail(res, 404, 'Creator not found');
    const feePercent = await pricing.platformFeePercent();
    res.json(pricing.quote(creator, req.query.video_count, feePercent));
  } catch (e) {
    return fail(res, e.status || 500, e.message);
  }
});

// POST /api/payments/orders  { creator_id, video_count, brief }
// Creates the Razorpay order. The client sends no prices — it can't be trusted to.
router.post('/orders', auth, async (req, res) => {
  try {
    if (req.user.role !== 'business') return fail(res, 403, 'Only brands can pay for a brief.');
    if (!rzp.isConfigured()) {
      return fail(res, 503, 'Payments are not switched on yet. Add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET on the server.');
    }

    const { creator_id, video_count, brief } = req.body;
    if (!creator_id || !mongoose.isValidObjectId(String(creator_id))) return fail(res, 400, 'A creator must be selected.');
    const creator = await User.findById(creator_id).lean();
    if (!creator || creator.role !== 'creator') return fail(res, 404, 'Creator not found');
    if (creator.approval_status !== 'approved') return fail(res, 400, 'This creator is not accepting briefs yet.');

    const feePercent = await pricing.platformFeePercent();
    const q = pricing.quote(creator, video_count, feePercent); // throws 400 if unpriceable

    // Our row first, so a webhook that races ahead of the browser still finds it.
    const order = await rzp.createOrder({
      amountRupees: q.total,
      receipt: `brief_${req.user.id}`.slice(0, 40),
      notes: { brand_id: String(req.user.id), creator_id: String(creator_id), purpose: 'brief' },
    });

    await PaymentOrder.create({
      rzp_order_id: order.id,
      purpose: 'brief',
      status: 'created',
      brand_id: req.user.id,
      creator_id,
      amount_subtotal: q.subtotal,
      fee_percent: q.fee_percent,
      amount_fee: q.fee,
      amount_total: q.total,
      currency: q.currency,
      brief: brief || {},
    });

    res.status(201).json({
      order_id: order.id,
      key_id: rzp.publicKeyId(),
      amount: order.amount,       // paise — what Razorpay's widget expects
      currency: order.currency,
      subtotal: q.subtotal,
      fee_percent: q.fee_percent,
      fee: q.fee,
      total: q.total,
      video_count: q.video_count,
    });
  } catch (e) {
    return fail(res, e.status || 500, e.message || 'Could not start the payment.');
  }
});

// Turn a paid order into the campaign + deal. Idempotent: a second call (webhook
// racing the browser, brand double-clicking, Razorpay retrying) returns the same
// campaign instead of creating another one and charging the brand twice over.
async function fulfil(order) {
  if (order.campaign_id) {
    const existing = await Campaign.findById(order.campaign_id).lean();
    if (existing) return existing;
  }

  const brief = order.brief || {};
  const campaign = await Campaign.create({
    ...brief,
    business_id: String(order.brand_id),
    selected_creator: String(order.creator_id),
    // Paid for, so it starts immediately — no admin approval gate, no bidding.
    status: 'in_progress',
    // The creator's take. The platform fee is charged on top and isn't escrowed.
    budget_min: order.amount_subtotal,
    budget_max: order.amount_subtotal,
    escrow_amount: order.amount_subtotal,
    platform_fee: order.amount_fee,
    amount_paid: order.amount_total,
    payment_order_id: order.rzp_order_id,
  });

  let deal = null;
  try {
    deal = await ensureDealForCampaign(campaign, String(order.creator_id), String(order.brand_id));
  } catch (e) {
    // The money is in and the campaign exists; a missing Deal Room is recoverable
    // (select-creator re-runs this), so don't fail the brand's payment over it.
    console.error('[payments] deal creation failed for order', order.rzp_order_id, e.message);
  }

  order.campaign_id = campaign._id;
  order.deal_id = deal ? deal.deal_id : null;
  await order.save();
  return campaign;
}

// POST /api/payments/verify — the browser's success callback.
// The signature is the whole point: without it, anyone could POST an order id and
// claim it was paid.
router.post('/verify', auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const order = await PaymentOrder.findOne({ rzp_order_id: razorpay_order_id });
    if (!order) return fail(res, 404, 'Unknown payment order.');
    if (String(order.brand_id) !== String(req.user.id)) return fail(res, 403, 'This payment belongs to another account.');

    const ok = rzp.verifyPaymentSignature({
      order_id: razorpay_order_id,
      payment_id: razorpay_payment_id,
      signature: razorpay_signature,
    });
    if (!ok) {
      order.status = 'failed';
      order.failure_reason = 'signature_mismatch';
      await order.save();
      return fail(res, 400, 'Payment could not be verified.');
    }

    if (order.status !== 'paid') {
      order.status = 'paid';
      order.rzp_payment_id = razorpay_payment_id;
      order.paid_at = new Date();
      await order.save();
    }

    const campaign = await fulfil(order);
    res.json({
      success: true,
      campaign_id: String(campaign._id),
      deal_id: order.deal_id,
      amount_paid: order.amount_total,
    });
  } catch (e) {
    return fail(res, e.status || 500, e.message || 'Payment verification failed.');
  }
});

// POST /api/payments/webhook — Razorpay's server-to-server truth.
// Fires even if the brand closes the tab mid-redirect, so the brief still goes
// live. No `auth` middleware: the HMAC over the raw body IS the authentication.
router.post('/webhook', async (req, res) => {
  try {
    if (!rzp.hasWebhookSecret()) return res.status(503).json({ detail: 'Webhook secret not configured.' });
    const signature = req.headers['x-razorpay-signature'];
    // req.rawBody is captured by express.json's verify hook in server.js — the HMAC
    // is over the exact bytes Razorpay sent, so a re-serialised body would not match.
    if (!rzp.verifyWebhookSignature(req.rawBody, signature)) {
      return res.status(400).json({ detail: 'Bad signature' });
    }

    const event = req.body && req.body.event;
    const entity = ((req.body.payload || {}).payment || {}).entity || {};
    const orderId = entity.order_id;
    if (!orderId) return res.json({ received: true });

    const order = await PaymentOrder.findOne({ rzp_order_id: orderId });
    if (!order) return res.json({ received: true });

    if (event === 'payment.captured') {
      if (order.status !== 'paid') {
        order.status = 'paid';
        order.rzp_payment_id = entity.id || order.rzp_payment_id;
        order.paid_at = new Date();
        await order.save();
      }
      await fulfil(order);
    } else if (event === 'payment.failed') {
      if (order.status !== 'paid') {
        order.status = 'failed';
        order.failure_reason = entity.error_description || 'payment_failed';
        await order.save();
      }
    }

    // Always 200 a signature-valid webhook, or Razorpay retries it forever.
    res.json({ received: true });
  } catch (e) {
    console.error('[payments] webhook error:', e.message);
    res.json({ received: true });
  }
});

module.exports = router;
