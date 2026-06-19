const express = require('express');
const router = express.Router();
const { auth, admin } = require('../middleware/auth');
const chat = require('../controllers/chatController');
const adminChat = require('../controllers/adminChatController');

// --- Admin oversight (declare BEFORE param routes so they don't get shadowed) ---
router.get('/admin/threads', auth, admin, adminChat.listThreads);
router.get('/admin/threads/:threadId', auth, admin, adminChat.viewThread);
router.post('/admin/threads/:threadId/join', auth, admin, adminChat.joinThread);
router.post('/admin/threads/:threadId/message', auth, admin, adminChat.postMessage);
router.get('/admin/threads/:threadId/export', auth, admin, adminChat.exportTranscript);
router.post('/admin/users/:userId/pause', auth, admin, adminChat.pauseUser);
router.post('/admin/users/:userId/downgrade', auth, admin, adminChat.downgradeUser);
router.post('/admin/users/:userId/restore', auth, admin, adminChat.restoreUser);
router.get('/admin/filter-log', auth, admin, adminChat.filterLog);
router.get('/admin/audit', auth, admin, adminChat.auditLog);

// --- Static named routes ---
router.get('/conversations', auth, chat.conversations);
router.get('/warnings', auth, chat.warnings);
router.post('/send', auth, chat.send);
router.post('/action-cards', auth, chat.createActionCard);
router.post('/action-cards/:cardId/respond', auth, chat.respondActionCard);
router.post('/report', auth, chat.reportUser);

// --- Param routes (last) ---
router.get('/:otherId/typing', auth, chat.getTyping);
router.post('/:otherId/typing', auth, chat.setTyping);
router.post('/:otherId/false-positive', auth, chat.flagFalsePositive);
router.get('/:otherId', auth, chat.getMessages);

module.exports = router;
