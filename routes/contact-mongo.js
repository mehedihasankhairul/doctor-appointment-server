import express from 'express';
import Contact from '../models/Contact.js';
import User from '../models/User.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { validateContact } from '../middleware/validation.js';

const router = express.Router();

// Submit contact form (public endpoint)
router.post('/', validateContact, async (req, res) => {
  try {
    const contactData = {
      ...req.body,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    };

    const contact = new Contact(contactData);
    await contact.save();

    res.status(201).json({
      message: 'Contact message submitted successfully. We will get back to you soon.',
      contact: {
        id: contact.id,
        name: contact.name,
        email: contact.email,
        subject: contact.subject,
        status: contact.status,
        createdAt: contact.createdAt
      }
    });
  } catch (error) {
    console.error('Submit contact error:', error);
    res.status(500).json({ error: 'Failed to submit contact message' });
  }
});

// Get all contact messages (admin/doctor only)
router.get('/', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, category, priority } = req.query;
    const skip = (page - 1) * limit;
    const filters = {};

    if (status) {
      filters.status = status;
    }

    if (category) {
      filters.category = category;
    }

    if (priority) {
      filters.priority = priority;
    }

    const contacts = await Contact.find(filters)
      .populate('assigned_to', 'full_name')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const totalCount = await Contact.countDocuments(filters);

    res.json({
      contacts,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalCount / limit),
        totalCount,
        hasNext: page * limit < totalCount,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch contacts error:', error);
    res.status(500).json({ error: 'Failed to fetch contact messages' });
  }
});

// Get single contact message
router.get('/:id', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;

    const contact = await Contact.findById(id)
      .populate('assigned_to', 'full_name')
      .populate('notes.author', 'full_name')
      .populate('response.author', 'full_name');

    if (!contact) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({ contact });
  } catch (error) {
    console.error('Fetch contact error:', error);
    res.status(500).json({ error: 'Failed to fetch contact message' });
  }
});

// Update contact message status/assignment (admin/doctor only)
router.patch('/:id/status', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, priority, assigned_to } = req.body;

    const updateData = {};
    if (status) updateData.status = status;
    if (priority) updateData.priority = priority;
    if (assigned_to) updateData.assigned_to = assigned_to;

    const contact = await Contact.findByIdAndUpdate(
      id,
      updateData,
      { new: true, runValidators: true }
    ).populate('assigned_to', 'full_name');

    if (!contact) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({
      message: 'Contact message updated successfully',
      contact
    });
  } catch (error) {
    console.error('Update contact error:', error);
    res.status(500).json({ error: 'Failed to update contact message' });
  }
});

// Add response to contact message (admin/doctor only)
router.post('/:id/response', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { text } = req.body;

    if (!text || text.trim() === '') {
      return res.status(400).json({ error: 'Response text is required' });
    }

    const contact = await Contact.findByIdAndUpdate(
      id,
      {
        response: {
          text: text.trim(),
          author: req.user.id,
          created_at: new Date()
        },
        status: 'resolved'
      },
      { new: true, runValidators: true }
    ).populate('assigned_to', 'full_name')
     .populate('response.author', 'full_name');

    if (!contact) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({
      message: 'Response added successfully',
      contact
    });
  } catch (error) {
    console.error('Add response error:', error);
    res.status(500).json({ error: 'Failed to add response' });
  }
});

// Add note to contact message (admin/doctor only)
router.post('/:id/notes', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { text } = req.body;

    if (!text || text.trim() === '') {
      return res.status(400).json({ error: 'Note text is required' });
    }

    const contact = await Contact.findByIdAndUpdate(
      id,
      {
        $push: {
          notes: {
            text: text.trim(),
            author: req.user.id,
            created_at: new Date()
          }
        }
      },
      { new: true, runValidators: true }
    ).populate('assigned_to', 'full_name')
     .populate('notes.author', 'full_name');

    if (!contact) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({
      message: 'Note added successfully',
      contact
    });
  } catch (error) {
    console.error('Add note error:', error);
    res.status(500).json({ error: 'Failed to add note' });
  }
});

// Delete contact message (admin only)
router.delete('/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;

    const contact = await Contact.findByIdAndDelete(id);

    if (!contact) {
      return res.status(404).json({ error: 'Contact message not found' });
    }

    res.json({ message: 'Contact message deleted successfully' });
  } catch (error) {
    console.error('Delete contact error:', error);
    res.status(500).json({ error: 'Failed to delete contact message' });
  }
});

// Get contact statistics (admin/doctor only)
router.get('/stats/overview', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const [totalContacts, newContacts, inProgressContacts, resolvedContacts, closedContacts] = await Promise.all([
      Contact.countDocuments(),
      Contact.countDocuments({ status: 'new' }),
      Contact.countDocuments({ status: 'in-progress' }),
      Contact.countDocuments({ status: 'resolved' }),
      Contact.countDocuments({ status: 'closed' })
    ]);

    const priorityStats = await Contact.aggregate([
      {
        $group: {
          _id: '$priority',
          count: { $sum: 1 }
        }
      }
    ]);

    const categoryStats = await Contact.aggregate([
      {
        $group: {
          _id: '$category',
          count: { $sum: 1 }
        }
      }
    ]);

    const monthlyStats = await Contact.aggregate([
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': -1, '_id.month': -1 }
      },
      {
        $limit: 12
      }
    ]);

    res.json({
      stats: {
        total_contacts: totalContacts,
        new_contacts: newContacts,
        in_progress_contacts: inProgressContacts,
        resolved_contacts: resolvedContacts,
        closed_contacts: closedContacts,
        contacts_by_priority: priorityStats,
        contacts_by_category: categoryStats,
        monthly_contacts: monthlyStats
      }
    });
  } catch (error) {
    console.error('Fetch contact stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

export default router;
