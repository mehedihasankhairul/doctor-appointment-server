import mongoose from 'mongoose';

const reviewSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Can be null for guest reviews
  },
  appointment_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Appointment',
    required: false // Can be null for general reviews
  },
  reviewer_name: {
    type: String,
    required: true,
    trim: true
  },
  reviewer_email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  review_text: {
    type: String,
    required: true,
    trim: true
  },
  hospital: {
    type: String,
    trim: true
  },
  doctor_name: {
    type: String,
    trim: true
  },
  service_type: {
    type: String,
    trim: true
  },
  is_verified: {
    type: Boolean,
    default: false
  },
  is_published: {
    type: Boolean,
    default: false
  },
  is_featured: {
    type: Boolean,
    default: false
  },
  helpful_count: {
    type: Number,
    default: 0
  },
  response: {
    text: String,
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    created_at: {
      type: Date,
      default: Date.now
    }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
reviewSchema.index({ rating: 1 });
reviewSchema.index({ is_published: 1 });
reviewSchema.index({ is_featured: 1 });
reviewSchema.index({ is_verified: 1 });
reviewSchema.index({ user_id: 1 });
reviewSchema.index({ appointment_id: 1 });
reviewSchema.index({ reviewer_email: 1 });
reviewSchema.index({ hospital: 1 });
reviewSchema.index({ doctor_name: 1 });
reviewSchema.index({ createdAt: -1 });

// Compound indexes
reviewSchema.index({ is_published: 1, createdAt: -1 });
reviewSchema.index({ rating: 1, is_published: 1 });
reviewSchema.index({ is_featured: 1, is_published: 1 });

const Review = mongoose.model('Review', reviewSchema);

export default Review;
