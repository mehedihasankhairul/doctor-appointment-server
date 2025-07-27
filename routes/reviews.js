import express from 'express';
import Review from '../models/Review.js';
import User from '../models/User.js';
import { authenticateToken, requireRole, optionalAuth } from '../middleware/auth.js';
import { validateReview } from '../middleware/validation.js';

const router = express.Router();

// Get all published reviews (public endpoint)
router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, rating } = req.query;
    const skip = (page - 1) * limit;
    const filters = { is_published: true };
    
    if (rating) {
      filters.rating = parseInt(rating);
    }

    const reviews = await Review.find(filters)
      .populate('user_id', 'full_name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    // Get stats using aggregation
    const statsAggregation = await Review.aggregate([
      { $match: { is_published: true } },
      {
        $group: {
          _id: null,
          totalCount: { $sum: 1 },
          averageRating: { $avg: '$rating' },
          ratingDistribution: {
            $push: '$rating'
          }
        }
      }
    ]);

    const stats = statsAggregation[0] || { totalCount: 0, averageRating: 0, ratingDistribution: [] };
    
    // Calculate rating distribution
    const ratingCounts = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    if (stats.ratingDistribution) {
      stats.ratingDistribution.forEach(rating => {
        ratingCounts[rating] = (ratingCounts[rating] || 0) + 1;
      });
    }

    res.json({
      reviews,
      stats: {
        totalCount: stats.totalCount,
        averageRating: parseFloat(stats.averageRating || 0).toFixed(1),
        ratingDistribution: ratingCounts
      },
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(stats.totalCount / limit),
        hasNext: page * limit < stats.totalCount,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch reviews error:', error);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// Get all reviews for admin (includes unpublished)
router.get('/admin', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, rating } = req.query;
    const skip = (page - 1) * limit;
    const filters = {};

    if (status === 'published') {
      filters.is_published = true;
    } else if (status === 'pending') {
      filters.is_published = false;
    }

    if (rating) {
      filters.rating = parseInt(rating);
    }

    const reviews = await Review.find(filters)
      .populate('user_id', 'full_name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Review.countDocuments(filters);

    res.json({
      reviews,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / limit),
        totalCount,
        hasNext: page * limit < totalCount,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch admin reviews error:', error);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// Create new review
router.post('/', optionalAuth, validateReview, async (req, res) => {
  try {
    const reviewData = {
      ...req.body,
      user_id: req.user ? req.user.id : null,
      reviewer_email: req.body.reviewer_email || (req.user ? req.user.email : req.body.patient_email)
    };

    const review = new Review(reviewData);
    await review.save();

    res.status(201).json({
      message: 'Review submitted successfully. It will be published after review.',
      review
    });
  } catch (error) {
    console.error('Create review error:', error);
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

// Get user's reviews
router.get('/my-reviews', authenticateToken, async (req, res) => {
  try {
    const reviews = await Review.find({ user_id: req.user.id })
      .sort({ createdAt: -1 });

    res.json({ reviews });
  } catch (error) {
    console.error('Fetch user reviews error:', error);
    res.status(500).json({ error: 'Failed to fetch your reviews' });
  }
});

// Get single review
router.get('/:id', optionalAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const review = await Review.findById(id)
      .populate('user_id', 'full_name');

    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }

    // Non-admin users can only see published reviews or their own
    if (!review.is_published && (!req.user || (req.user.role !== 'admin' && req.user.role !== 'doctor' && review.user_id?.toString() !== req.user.id))) {
      return res.status(404).json({ error: 'Review not found' });
    }

    res.json({ review });
  } catch (error) {
    console.error('Fetch review error:', error);
    res.status(500).json({ error: 'Failed to fetch review' });
  }
});

// Update review (user can edit their own unpublished reviews)
router.put('/:id', authenticateToken, validateReview, async (req, res) => {
  try {
    const { id } = req.params;
    const { reviewer_name, rating, review_text } = req.body;

    const review = await Review.findById(id);

    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }

    // Users can only edit their own unpublished reviews
    if (review.user_id?.toString() !== req.user.id) {
      return res.status(403).json({ error: 'You can only edit your own reviews' });
    }

    if (review.is_published) {
      return res.status(400).json({ error: 'Cannot edit published reviews' });
    }

    const updatedReview = await Review.findByIdAndUpdate(
      id,
      { reviewer_name, rating, review_text },
      { new: true, runValidators: true }
    );

    res.json({
      message: 'Review updated successfully',
      review: updatedReview
    });
  } catch (error) {
    console.error('Update review error:', error);
    res.status(500).json({ error: 'Failed to update review' });
  }
});

// Publish/unpublish review (admin/doctor only)
router.patch('/:id/publish', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { is_published, is_verified = false } = req.body;

    const review = await Review.findByIdAndUpdate(
      id,
      { is_published, is_verified },
      { new: true, runValidators: true }
    );

    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }

    res.json({
      message: `Review ${is_published ? 'published' : 'unpublished'} successfully`,
      review
    });
  } catch (error) {
    console.error('Publish review error:', error);
    res.status(500).json({ error: 'Failed to update review status' });
  }
});

// Delete review
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const review = await Review.findById(id);

    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }

    // Users can delete their own reviews, admins can delete any
    if (req.user.role !== 'admin' && review.user_id?.toString() !== req.user.id) {
      return res.status(403).json({ error: 'You can only delete your own reviews' });
    }

    await Review.findByIdAndDelete(id);

    res.json({ message: 'Review deleted successfully' });
  } catch (error) {
    console.error('Delete review error:', error);
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

// Get review statistics (admin/doctor only)
router.get('/stats/overview', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const [totalReviews, publishedReviews, pendingReviews, verifiedReviews] = await Promise.all([
      Review.countDocuments(),
      Review.countDocuments({ is_published: true }),
      Review.countDocuments({ is_published: false }),
      Review.countDocuments({ is_verified: true })
    ]);

    const ratingStats = await Review.aggregate([
      {
        $group: {
          _id: null,
          averageRating: { $avg: '$rating' },
          fiveStarReviews: { $sum: { $cond: [{ $eq: ['$rating', 5] }, 1, 0] } },
          fourStarReviews: { $sum: { $cond: [{ $eq: ['$rating', 4] }, 1, 0] } },
          threeStarReviews: { $sum: { $cond: [{ $eq: ['$rating', 3] }, 1, 0] } },
          twoStarReviews: { $sum: { $cond: [{ $eq: ['$rating', 2] }, 1, 0] } },
          oneStarReviews: { $sum: { $cond: [{ $eq: ['$rating', 1] }, 1, 0] } }
        }
      }
    ]);

    const stats = ratingStats[0] || {};

    res.json({
      stats: {
        total_reviews: totalReviews,
        published_reviews: publishedReviews,
        pending_reviews: pendingReviews,
        verified_reviews: verifiedReviews,
        average_rating: parseFloat(stats.averageRating || 0).toFixed(1),
        five_star_reviews: stats.fiveStarReviews || 0,
        four_star_reviews: stats.fourStarReviews || 0,
        three_star_reviews: stats.threeStarReviews || 0,
        two_star_reviews: stats.twoStarReviews || 0,
        one_star_reviews: stats.oneStarReviews || 0
      }
    });
  } catch (error) {
    console.error('Fetch review stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

export default router;
