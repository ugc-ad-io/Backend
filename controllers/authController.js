const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { MIN_CHAT_BALANCE } = require('../utils/chatPolicy');

const fail = (res, status, detail) => res.status(status).json({ detail });

// Email that is always the platform founder (PRD 11 — Role structure).
const FOUNDER_EMAIL = (process.env.FOUNDER_EMAIL || 'admin@gmail.com').toLowerCase();

function signToken(user) {
  return jwt.sign(
    { id: user._id, role: user.role, admin_role: user.admin_role || null },
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
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

    // Block banned / deactivated / suspended accounts from logging in.
    // Toggle: enforcement is OFF unless ENFORCE_BANS=true (temporarily disabled).
    if (process.env.ENFORCE_BANS === 'true') {
      if (user.banned) return fail(res, 403, user.ban_reason ? `Your account has been banned: ${user.ban_reason}` : 'Your account has been banned. Contact support.');
      if (user.active === false) return fail(res, 403, 'Your account has been deactivated. Contact support.');
      if (user.suspended_until && new Date(user.suspended_until) > new Date()) {
        return fail(res, 403, `Your account is suspended until ${new Date(user.suspended_until).toLocaleDateString()}.`);
      }
    }

    // The founder account is always admin + founder — self-heal on login.
    if (user.email === FOUNDER_EMAIL && (user.role !== 'admin' || user.admin_role !== 'founder')) {
      user.role = 'admin';
      user.admin_role = 'founder';
      await user.save();
    }

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

// Persist the full onboarding form to the user, then mark it pending review.
// Stores every submitted field verbatim under `profile` so admin review and the
// approvals modal can show everything the creator/business filled in.
async function saveOnboardingProfile(req, res, next, role) {
  try {
    if (req.user.role !== role) {
      return fail(res, 403, `Only ${role}s can update the ${role} profile`);
    }
    const data = { ...(req.body || {}) };
    const username = typeof data.username === 'string' ? data.username.trim() : null;

    const set = {
      profile: data,
      profile_completed: true,
      approval_status: 'pending',
      submitted_at: new Date()
    };
    // Mirror a few fields onto the top-level user so existing reads keep working.
    const photo = data.profile_picture || data.profile_photo || data.logo;
    if (photo) set.profile_photo = photo;
    if (data.nickname || data.full_name || data.business_name) {
      set.nickname = data.nickname || data.full_name || data.business_name;
    }
    if (Array.isArray(data.portfolio)) set.portfolio = data.portfolio;
    if (username) set.username = username;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: set },
      { new: true }
    );
    if (!user) return fail(res, 404, 'User not found');
    res.json({ message: 'Profile submitted for review', username: username || null });
  } catch (err) {
    next(err);
  }
}

// PUT /api/profile/creator  — save the creator onboarding form
exports.updateCreatorProfile = (req, res, next) => saveOnboardingProfile(req, res, next, 'creator');

// PUT /api/profile/business — save the business onboarding form
exports.updateBusinessProfile = (req, res, next) => saveOnboardingProfile(req, res, next, 'business');

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
