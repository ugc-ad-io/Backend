const express = require('express');
const router = express.Router();
const { auth, admin } = require('../middleware/auth');
const {
  createGig,
  listGigs,
  getGigById,
  updateGigStatus,
  getGigsByCreator
} = require('../controllers/gigController');

// Create a new gig (requires authentication)
router.post('/', auth, createGig);

// List all gigs with filters
router.get('/', listGigs);

// Get gigs by creator
router.get('/creator/:creatorId', getGigsByCreator);

// Get single gig by ID
router.get('/:id', getGigById);

// Update gig status (admin only)
router.patch('/:id', auth, admin, updateGigStatus);

module.exports = router;
