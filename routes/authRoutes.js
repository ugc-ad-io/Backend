const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const ctrl = require('../controllers/authController');

router.post('/signup', ctrl.signup);
router.post('/login', ctrl.login);
router.post('/google', ctrl.googleAuth);
router.post('/forgot-password', ctrl.forgotPassword);
router.post('/verify-reset-code', ctrl.verifyResetCode);
router.post('/reset-password', ctrl.resetPassword);
router.get('/me', auth, ctrl.me);

module.exports = router;
