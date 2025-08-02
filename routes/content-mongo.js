import express from 'express';
import Content from '../models/Content.js';
import User from '../models/User.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { validateContent } from '../middleware/validation.js';
import NodeCache from 'node-cache';

const router = express.Router();

// Initialize cache with 15 minute TTL
const cache = new NodeCache({ 
  stdTTL: 900, // 15 minutes
  checkperiod: 120, // Check for expired keys every 2 minutes
  useClones: false
});

// Cache keys
const CACHE_KEYS = {
  PUBLIC_CONTENT: 'public_content',
  ADMIN_CONTENT: 'admin_content',
  CONTENT_STATS: 'content_stats',
  FEATURED_CONTENT: 'featured_content'
};

// Helper function to clear relevant cache
const clearContentCache = () => {
  cache.del([CACHE_KEYS.PUBLIC_CONTENT, CACHE_KEYS.ADMIN_CONTENT, CACHE_KEYS.CONTENT_STATS, CACHE_KEYS.FEATURED_CONTENT]);
};

// Get all published content (public endpoint)
router.get('/', async (req, res) => {
  try {
    const { category, content_type, search, page = 1, limit = 12 } = req.query;
    const skip = (page - 1) * limit;
    const filters = { is_published: true };

    if (category) {
      filters.category = category;
    }

    if (content_type) {
      filters.content_type = content_type;
    }

    if (search) {
      filters.$or = [
        { title: new RegExp(search, 'i') },
        { description: new RegExp(search, 'i') }
      ];
    }

    const content = await Content.find(filters)
      .populate('author', 'full_name')
      .sort({ published_date: -1, createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Content.countDocuments(filters);

    res.json({
      content,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / limit),
        totalCount,
        hasNext: page * limit < totalCount,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch content error:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

// Get all content for admin/doctor (includes unpublished)
router.get('/admin', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, category, content_type } = req.query;
    const skip = (page - 1) * limit;
    const filters = {};

    if (status === 'published') {
      filters.is_published = true;
    } else if (status === 'draft') {
      filters.is_published = false;
    }

    if (category) {
      filters.category = category;
    }

    if (content_type) {
      filters.content_type = content_type;
    }

    const content = await Content.find(filters)
      .populate('author', 'full_name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Content.countDocuments(filters);

    res.json({
      content,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / limit),
        totalCount,
        hasNext: page * limit < totalCount,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch admin content error:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

// Get single content item
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const content = await Content.findById(id)
      .populate('author', 'full_name');

    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    // Non-admin users can only see published content
    if (!content.is_published && (!req.user || (req.user.role !== 'admin' && req.user.role !== 'doctor'))) {
      return res.status(404).json({ error: 'Content not found' });
    }

    // Increment view count
    await Content.findByIdAndUpdate(id, { $inc: { view_count: 1 } });

    res.json({ content });
  } catch (error) {
    console.error('Fetch content error:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

// Create new content (doctor/admin only)
router.post('/', authenticateToken, requireRole(['admin', 'doctor']), validateContent, async (req, res) => {
  try {
    const contentData = {
      ...req.body,
      author: req.user.id,
      published_date: req.body.is_published ? new Date() : null
    };

    const content = new Content(contentData);
    await content.save();

    res.status(201).json({
      message: 'Content created successfully',
      content
    });
  } catch (error) {
    console.error('Create content error:', error);
    res.status(500).json({ error: 'Failed to create content' });
  }
});

// Update content (doctor/admin only)
router.put('/:id', authenticateToken, requireRole(['admin', 'doctor']), validateContent, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = { ...req.body };

    // Set published_date if publishing for the first time
    if (req.body.is_published && !updateData.published_date) {
      updateData.published_date = new Date();
    }

    const content = await Content.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    ).populate('author', 'full_name');

    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    res.json({
      message: 'Content updated successfully',
      content
    });
  } catch (error) {
    console.error('Update content error:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
});

// Delete content (admin only)
router.delete('/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const content = await Content.findByIdAndDelete(id);

    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    res.json({ message: 'Content deleted successfully' });
  } catch (error) {
    console.error('Delete content error:', error);
    res.status(500).json({ error: 'Failed to delete content' });
  }
});

// Toggle featured status (admin only)
router.patch('/:id/featured', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    const { is_featured } = req.body;

    const content = await Content.findByIdAndUpdate(
      id,
      { is_featured },
      { new: true, runValidators: true }
    );

    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }

    res.json({
      message: `Content ${is_featured ? 'featured' : 'unfeatured'} successfully`,
      content
    });
  } catch (error) {
    console.error('Toggle featured error:', error);
    res.status(500).json({ error: 'Failed to update featured status' });
  }
});

// Get content statistics (admin/doctor only)
router.get('/stats/overview', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const [totalContent, publishedContent, draftContent, featuredContent] = await Promise.all([
      Content.countDocuments(),
      Content.countDocuments({ is_published: true }),
      Content.countDocuments({ is_published: false }),
      Content.countDocuments({ is_featured: true })
    ]);

    const typeStats = await Content.aggregate([
      {
        $group: {
          _id: '$content_type',
          count: { $sum: 1 }
        }
      }
    ]);

    const categoryStats = await Content.aggregate([
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      }
    ]);

    const viewStats = await Content.aggregate([
      {
        $group: {
          _id: null,
          totalViews: { $sum: '$view_count' },
          averageViews: { $avg: '$view_count' }
        }
      }
    ]);

    res.json({
      stats: {
        total_content: totalContent,
        published_content: publishedContent,
        draft_content: draftContent,
        featured_content: featuredContent,
        total_views: viewStats[0]?.totalViews || 0,
        average_views: Math.round(viewStats[0]?.averageViews || 0),
        content_by_type: typeStats,
        content_by_category: categoryStats
      }
    });
  } catch (error) {
    console.error('Fetch content stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

export default router;
