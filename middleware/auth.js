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

    // Shared brand workspace: a team member acts on the OWNER's brand data, but
    // keeps their own identity (id) for chat, notifications and audit. Every
    // brand-scoped query should read req.user.workspace_id, not req.user.id.
    // Falls back to the user's own id for owners and older tokens (no team_of).
    req.user.workspace_id = decoded.team_of || decoded.id;
    req.user.team_role = decoded.team_role || 'owner';

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

// Block a read-only team member (team_role === 'viewer') from mutating the
// brand's workspace. Owners/admins/members pass through.
const brandWrite = (req, res, next) => {
  if (req.user && req.user.team_role === 'viewer') {
    return res.status(403).json({ detail: 'Your team role is view-only. Ask a workspace admin for edit access.' });
  }
  next();
};

// The brand whose data this request operates on: the owner for a team member,
// the user themselves otherwise.
const workspaceId = (req) => (req.user && (req.user.workspace_id || req.user.id));

module.exports = { auth, admin, brandWrite, workspaceId };
