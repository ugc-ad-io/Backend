const Joi = require('joi');

const createGigSchema = Joi.object({
  title: Joi.string()
    .required()
    .min(5)
    .max(100)
    .trim()
    .messages({
      'string.empty': 'Title is required',
      'string.min': 'Title must be at least 5 characters',
      'string.max': 'Title cannot exceed 100 characters'
    }),
  description: Joi.string()
    .required()
    .min(20)
    .max(5000)
    .messages({
      'string.empty': 'Description is required',
      'string.min': 'Description must be at least 20 characters',
      'string.max': 'Description cannot exceed 5000 characters'
    }),
  category: Joi.string()
    .required()
    .valid(
      'SOCIAL_MEDIA',
      'PRODUCT_REVIEW',
      'UNBOXING',
      'TUTORIAL',
      'SPONSORSHIP',
      'BRAND_AMBASSADOR',
      'CONTENT_CREATION',
      'PHOTOGRAPHY',
      'VIDEOGRAPHY',
      'OTHER'
    )
    .messages({
      'any.only': 'Invalid category selected'
    }),
  budget: Joi.number()
    .required()
    .min(0.01)
    .messages({
      'number.min': 'Budget must be greater than 0'
    }),
  deadline: Joi.date()
    .required()
    .greater('now')
    .messages({
      'date.base': 'Deadline must be a valid date',
      'date.greater': 'Deadline must be in the future'
    }),
  attachments: Joi.array().items(Joi.string().uri()).default([]),
  requirements: Joi.string().max(2000).allow('').default(''),
  target_audience: Joi.string().max(500).allow('').default(''),
  skills_required: Joi.array().items(Joi.string()).default([])
});

const updateGigStatusSchema = Joi.object({
  status: Joi.string()
    .required()
    .valid('APPROVED', 'REJECTED')
    .messages({
      'any.only': 'Status must be either APPROVED or REJECTED'
    }),
  rejectionReason: Joi.when('status', {
    is: 'REJECTED',
    then: Joi.string()
      .required()
      .max(1000)
      .messages({
        'string.empty': 'Rejection reason is required when rejecting a gig'
      }),
    otherwise: Joi.string().max(1000).allow('')
  })
});

const listGigsSchema = Joi.object({
  status: Joi.string().valid('PENDING', 'APPROVED', 'REJECTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'),
  category: Joi.string(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(10),
  sortBy: Joi.string().default('createdAt'),
  search: Joi.string().allow('')
});

module.exports = {
  createGigSchema,
  updateGigStatusSchema,
  listGigsSchema
};
