const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Authentication token is required'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    // Reject banned / deactivated / suspended accounts even with a valid token,
    // so a ban takes effect immediately (kills existing sessions too).
    // Toggle: enforcement is OFF unless ENFORCE_BANS=true (temporarily disabled).
    if (process.env.ENFORCE_BANS === 'true') {
      try {
        const u = await User.findById(decoded.id).select('banned active suspended_until').lean();
        if (u) {
          if (u.banned) return res.status(403).json({ success: false, message: 'Your account has been banned.' });
          if (u.active === false) return res.status(403).json({ success: false, message: 'Your account has been deactivated.' });
          if (u.suspended_until && new Date(u.suspended_until) > new Date()) {
            return res.status(403).json({ success: false, message: 'Your account is suspended.' });
          }
        }
      } catch (e) { /* DB hiccup — don't lock everyone out over a transient error */ }
    }

    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

const admin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
  next();
};

module.exports = { auth, admin };
