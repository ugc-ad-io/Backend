const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const ctrl = require('../controllers/authController');

// Onboarding form submit — persist the full creator/business profile.
// Declared before the catch-all GET so they don't get shadowed.
router.put('/creator', auth, ctrl.updateCreatorProfile);
router.put('/business', auth, ctrl.updateBusinessProfile);

// Public profile (chat header / quick view)
router.get('/:userId', auth, ctrl.publicProfile);

module.exports = router;
