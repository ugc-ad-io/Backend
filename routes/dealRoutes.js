const express = require('express');
const router = express.Router();
const { auth, admin } = require('../middleware/auth');
const ctrl = require('../controllers/dealController');

// Reads
router.get('/my', auth, ctrl.myDeals);
router.get('/', auth, admin, ctrl.listAllDeals);

// Dev seed
router.post('/seed', auth, ctrl.seedDemo);

// Brand actions
router.post('/:dealId/tracking', auth, ctrl.uploadTracking);
router.post('/:dealId/delivered', auth, ctrl.markDelivered);
router.post('/:dealId/approve', auth, ctrl.approve);
router.post('/:dealId/request-revision', auth, ctrl.requestRevision);

// Creator actions
router.post('/:dealId/receipt', auth, ctrl.submitReceipt);
router.post('/:dealId/content', auth, ctrl.submitContent);
router.post('/:dealId/revision-response', auth, ctrl.revisionResponse);

// Shared actions
router.post('/:dealId/chat', auth, ctrl.sendChat);
router.post('/:dealId/action-card', auth, ctrl.createActionCard);
router.post('/:dealId/escalate', auth, ctrl.escalate);
router.post('/:dealId/dispute', auth, ctrl.raiseDispute);
router.post('/:dealId/damage-report', auth, ctrl.damageReport);
router.post('/:dealId/archive', auth, ctrl.archive);

// Admin intervention
router.post('/:dealId/resolve', auth, admin, ctrl.adminResolve);
router.post('/:dealId/release', auth, admin, ctrl.adminRelease);

// Single deal (keep last so it doesn't shadow the named routes above)
router.get('/:dealId', auth, ctrl.getDeal);

module.exports = router;
