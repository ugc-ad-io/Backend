// Calculate application deadline in days
const getDaysUntilDeadline = (deadline) => {
  const now = new Date();
  const deadlineDate = new Date(deadline);
  const difference = deadlineDate - now;
  const days = Math.ceil(difference / (1000 * 60 * 60 * 24));
  return days;
};

// Check if deadline is within x days
const isDeadlineWithinDays = (deadline, days) => {
  return getDaysUntilDeadline(deadline) <= days;
};

// Format gig response with calculated fields
const formatGigResponse = (gig) => {
  const daysUntilDeadline = getDaysUntilDeadline(gig.deadline);
  return {
    ...gig.toObject(),
    daysUntilDeadline,
    isUrgent: daysUntilDeadline <= 7
  };
};

// Build filter query
const buildGigFilter = (query) => {
  const filter = {};

  if (query.status) {
    filter.status = query.status;
  }

  if (query.category) {
    filter.category = query.category;
  }

  if (query.creator_id) {
    filter.creator_id = query.creator_id;
  }

  if (query.search) {
    filter.$or = [
      { title: { $regex: query.search, $options: 'i' } },
      { description: { $regex: query.search, $options: 'i' } }
    ];
  }

  if (query.min_budget && query.max_budget) {
    filter.budget = {
      $gte: query.min_budget,
      $lte: query.max_budget
    };
  }

  return filter;
};

// Calculate pagination
const getPagination = (page = 1, limit = 10) => {
  const pageNum = Math.max(1, parseInt(page));
  const limitNum = Math.max(1, Math.min(100, parseInt(limit)));
  const skip = (pageNum - 1) * limitNum;

  return { skip, limit: limitNum, page: pageNum };
};

module.exports = {
  getDaysUntilDeadline,
  isDeadlineWithinDays,
  formatGigResponse,
  buildGigFilter,
  getPagination
};
