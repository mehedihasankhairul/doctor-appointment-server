import mongoose from 'mongoose';

const contentSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    trim: true
  },
  content_type: {
    type: String,
    required: true,
    enum: ['youtube', 'facebook', 'article', 'image', 'video'],
    lowercase: true
  },
  content_url: {
    type: String,
    required: true,
    trim: true
  },
  thumbnail_url: {
    type: String,
    trim: true
  },
  category: {
    type: String,
    trim: true,
    default: 'general'
  },
  tags: [{
    type: String,
    trim: true
  }],
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  is_published: {
    type: Boolean,
    default: false
  },
  is_featured: {
    type: Boolean,
    default: false
  },
  view_count: {
    type: Number,
    default: 0
  },
  like_count: {
    type: Number,
    default: 0
  },
  published_date: {
    type: Date
  },
  metadata: {
    duration: String,
    file_size: Number,
    dimensions: {
      width: Number,
      height: Number
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
contentSchema.index({ content_type: 1 });
contentSchema.index({ is_published: 1 });
contentSchema.index({ is_featured: 1 });
contentSchema.index({ author: 1 });
contentSchema.index({ category: 1 });
contentSchema.index({ tags: 1 });
contentSchema.index({ published_date: -1 });

// Compound indexes
contentSchema.index({ is_published: 1, published_date: -1 });
contentSchema.index({ content_type: 1, is_published: 1 });

const Content = mongoose.model('Content', contentSchema);

export default Content;
