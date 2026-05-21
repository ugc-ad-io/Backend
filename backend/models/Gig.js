const mongoose = require('mongoose');

const gigSchema = new mongoose.Schema(
  {
    title: {
      type: String,
      required: [true, 'Gig title is required'],
      trim: true,
      maxlength: [100, 'Title cannot exceed 100 characters'],
      minlength: [5, 'Title must be at least 5 characters']
    },
    description: {
      type: String,
      required: [true, 'Gig description is required'],
      maxlength: [5000, 'Description cannot exceed 5000 characters'],
      minlength: [20, 'Description must be at least 20 characters']
    },
    category: {
      type: String,
      enum: [
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
      ],
      required: [true, 'Category is required']
    },
    budget: {
      type: Number,
      required: [true, 'Budget is required'],
      min: [0.01, 'Budget must be greater than 0']
    },
    deadline: {
      type: Date,
      required: [true, 'Deadline is required'],
      validate: {
        validator: function(v) {
          return v > new Date();
        },
        message: 'Deadline must be in the future'
      }
    },
    status: {
      type: String,
      enum: ['PENDING', 'APPROVED', 'REJECTED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'],
      default: 'PENDING'
    },
    creator_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'Creator ID is required']
    },
    attachments: {
      type: [String],
      default: []
    },
    requirements: {
      type: String,
      maxlength: [2000, 'Requirements cannot exceed 2000 characters']
    },
    target_audience: {
      type: String,
      maxlength: [500, 'Target audience description cannot exceed 500 characters']
    },
    skills_required: {
      type: [String],
      default: []
    },
    applications_count: {
      type: Number,
      default: 0
    },
    selected_creator_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    },
    rejectionReason: {
      type: String,
      maxlength: [1000, 'Rejection reason cannot exceed 1000 characters']
    }
  },
  {
    timestamps: true
  }
);

gigSchema.index({ creator_id: 1 });
gigSchema.index({ status: 1 });
gigSchema.index({ created_at: -1 });

module.exports = mongoose.model('Gig', gigSchema);
