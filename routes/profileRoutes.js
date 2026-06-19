const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const ctrl = require('../controllers/authController');

// Public profile (chat header / quick view)
router.get('/:userId', auth, ctrl.publicProfile);

module.exports = router;
