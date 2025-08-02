import express from 'express';
import { authenticateToken, requireRole } from '../middleware/auth.js';

const router = express.Router();

import Content from '../models/Content.js';
import User from '../models/User.js';

router.get('/', async (req, res) => {
  try {
    const { page = 1, limit = 10, category } = req.query;
    const skip = (page - 1) * limit;
    const filters = {};

    if (category) {
      filters.category = category;
    }

    const contentList = await Content.find(filters)
      .populate('author', 'full_name')
      .sort({ published_date: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Content.countDocuments(filters);

    res.json({
      content: contentList,
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

router.post('/', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { title, description, content_type, content_url, thumbnail_url, category, tags, is_published, is_featured } = req.body;

    const author = await User.findById(req.user.id);
    if (!author) {
      return res.status(404).json({ error: 'Author not found' });
    }

    const content = new Content({
      title,
      description,
      content_type,
      content_url,
      thumbnail_url,
      category,
      tags,
      author: author._id,
      is_published,
      is_featured,
      published_date: is_published ? new Date() : undefined
    });

    await content.save();

    res.status(201).json({
      message: 'Content created successfully',
      content
    });
  } catch (error) {
    console.error('Post content error:', error);
    res.status(500).json({ error: 'Failed to post content' });
  }
});

// Get single content by ID
router.get('/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const content = await Content.findById(id).populate('author', 'full_name');
    
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    // Increment view count
    content.view_count += 1;
    await content.save();
    
    res.json({ content });
  } catch (error) {
    console.error('Fetch content error:', error);
    res.status(500).json({ error: 'Failed to fetch content' });
  }
});

// Update content
router.put('/:id', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const content = await Content.findByIdAndUpdate(
      id,
      updates,
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

// Delete content
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


export default router;
