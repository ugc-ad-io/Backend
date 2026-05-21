const Gig = require('../models/Gig');
const { createGigSchema, updateGigStatusSchema, listGigsSchema } = require('../validation/gigValidation');

// POST /api/gigs - Creator submits a new gig
exports.createGig = async (req, res, next) => {
  try {
    // Validate input
    const { error, value } = createGigSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: error.details.map(d => d.message)
      });
    }

    // Create gig
    const gig = new Gig({
      ...value,
      creator_id: req.user.id
    });

    await gig.save();

    res.status(201).json({
      success: true,
      message: 'Gig created successfully',
      data: gig
    });
  } catch (error) {
    next(error);
  }
};

// GET /api/gigs - List all gigs with filters
exports.listGigs = async (req, res, next) => {
  try {
    // Validate query parameters
    const { error, value } = listGigsSchema.validate(req.query);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid query parameters'
      });
    }

    const { status, category, page, limit, sortBy, search } = value;

    // Build filter object
    const filter = {};
    if (status) filter.status = status;
    if (category) filter.category = category;
    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }

    // Calculate pagination
    const skip = (page - 1) * limit;

    // Fetch gigs
    const gigs = await Gig.find(filter)
      .populate('creator_id', 'name email profile_image')
      .sort({ [sortBy]: -1 })
      .skip(skip)
      .limit(limit);

    // Count total
    const total = await Gig.countDocuments(filter);

    res.json({
      success: true,
      data: gigs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    next(error);
  }
};

// GET /api/gigs/:id - Get single gig
exports.getGigById = async (req, res, next) => {
  try {
    const gig = await Gig.findById(req.params.id)
      .populate('creator_id', 'name email profile_image')
      .populate('selected_creator_id', 'name email profile_image');

    if (!gig) {
      return res.status(404).json({
        success: false,
        message: 'Gig not found'
      });
    }

    res.json({
      success: true,
      data: gig
    });
  } catch (error) {
    next(error);
  }
};

// PATCH /api/gigs/:id - Admin approve or reject gig
exports.updateGigStatus = async (req, res, next) => {
  try {
    // Validate input
    const { error, value } = updateGigStatusSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: error.details.map(d => d.message)
      });
    }

    const gig = await Gig.findById(req.params.id);

    if (!gig) {
      return res.status(404).json({
        success: false,
        message: 'Gig not found'
      });
    }

    // Check if gig is still pending
    if (gig.status !== 'PENDING') {
      return res.status(400).json({
        success: false,
        message: 'Can only update gigs with PENDING status'
      });
    }

    // Update status
    gig.status = value.status;
    if (value.rejectionReason) {
      gig.rejectionReason = value.rejectionReason;
    }

    await gig.save();

    res.json({
      success: true,
      message: `Gig ${value.status.toLowerCase()} successfully`,
      data: gig
    });
  } catch (error) {
    next(error);
  }
};

// GET /api/gigs/creator/:creatorId - Get all gigs by a creator
exports.getGigsByCreator = async (req, res, next) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    const skip = (page - 1) * limit;

    const filter = { creator_id: req.params.creatorId };
    if (status) filter.status = status;

    const gigs = await Gig.find(filter)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Gig.countDocuments(filter);

    res.json({
      success: true,
      data: gigs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    next(error);
  }
};
