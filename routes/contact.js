import express from 'express';
import { authenticateToken, requireRole } from '../middleware/auth.js';

const router = express.Router();

// Submit contact message (public endpoint) - Placeholder
router.post('/', async (req, res) => {
  try {
    res.status(201).json({
      message: 'Contact route not implemented yet',
    });
  } catch (error) {
    console.error('Contact message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});


export default router;
