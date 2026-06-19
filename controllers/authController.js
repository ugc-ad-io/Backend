const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { MIN_CHAT_BALANCE } = require('../utils/chatPolicy');

const fail = (res, status, detail) => res.status(status).json({ detail });

function signToken(user) {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '30d' });
}

// POST /api/auth/signup { email, password, role }
exports.signup = async (req, res, next) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return fail(res, 400, 'Email and password are required');
    if (await User.findOne({ email: email.toLowerCase() })) return fail(res, 409, 'An account with this email already exists');

    const user = await User.create({
      email,
      password,
      role: ['creator', 'business', 'admin'].includes(role) ? role : 'creator',
      nickname: email.split('@')[0]
    });

    res.status(201).json({ token: signToken(user), ...user.toSelf() });
  } catch (err) {
    next(err);
  }
};

// POST /api/auth/login { email, password }
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return fail(res, 400, 'Email and password are required');

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user || !(await user.comparePassword(password))) return fail(res, 401, 'Invalid email or password');

    res.json({ token: signToken(user), ...user.toSelf() });
  } catch (err) {
    next(err);
  }
};

// GET /api/auth/me
exports.me = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return fail(res, 404, 'User not found');
    res.json(user.toSelf());
  } catch (err) {
    next(err);
  }
};

// GET /api/profile/:userId  (public profile for chat header / quick view)
exports.publicProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) return fail(res, 404, 'User not found');
    res.json(user.toPublic());
  } catch (err) {
    next(err);
  }
};

// PUT /api/settings/chat { read_receipts, notifications, timezone }
exports.updateChatSettings = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return fail(res, 404, 'User not found');
    const { read_receipts, notifications, timezone } = req.body;
    if (typeof read_receipts === 'boolean') user.settings.read_receipts = read_receipts;
    if (notifications && typeof notifications === 'object') {
      user.settings.notifications = { ...user.settings.notifications, ...notifications };
    }
    if (timezone) user.settings.timezone = timezone;
    await user.save();
    res.json(user.toSelf());
  } catch (err) {
    next(err);
  }
};

// GET /api/business/wallet  — wallet state + chat gate (10.2)
exports.getWallet = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return fail(res, 404, 'User not found');
    res.json({
      available_balance: user.wallet_balance,
      minimum_chat_balance: MIN_CHAT_BALANCE,
      chat_unlocked: user.wallet_balance >= MIN_CHAT_BALANCE,
      recharge_bonus: {},
      transactions: []
    });
  } catch (err) {
    next(err);
  }
};

// POST /api/business/wallet/recharge { amount }
exports.rechargeWallet = async (req, res, next) => {
  try {
    const amount = Number(req.body.amount);
    if (!amount || amount < MIN_CHAT_BALANCE) return fail(res, 400, `Minimum recharge amount is Rs. ${MIN_CHAT_BALANCE.toLocaleString('en-IN')}`);
    const user = await User.findById(req.user.id);
    if (!user) return fail(res, 404, 'User not found');
    user.wallet_balance += amount;
    await user.save();
    res.json({
      available_balance: user.wallet_balance,
      minimum_chat_balance: MIN_CHAT_BALANCE,
      chat_unlocked: user.wallet_balance >= MIN_CHAT_BALANCE,
      message: 'Wallet recharged'
    });
  } catch (err) {
    next(err);
  }
};
