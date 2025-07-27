import jwt from 'jsonwebtoken';
import { getCollection, toObjectId } from '../config/database.js';

// Authenticate JWT token
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Handle demo token for development
    if (token === 'demo-doctor-token' && process.env.NODE_ENV !== 'production') {
      req.user = {
        id: 'demo-doctor-id',
        email: 'doctor@example.com',
        full_name: 'Dr. Demo',
        role: 'doctor'
      };
      return next();
    }

    // Verify JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Bypass ObjectId conversion for demo users
    if (decoded.id === 'demo-doctor-id') {
      req.user = {
        id: decoded.id,
        email: decoded.email,
        full_name: decoded.full_name,
        role: decoded.role
      };
      return next();
    }

    // Get fresh user data from database
    const usersCollection = getCollection('users');
    const user = await usersCollection.findOne(
      { _id: toObjectId(decoded.id) },
      { projection: { email: 1, full_name: 1, role: 1 } }
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid token - user not found' });
    }

    req.user = {
      id: user._id.toString(),
      email: user.email,
      full_name: user.full_name,
      role: user.role
    };
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({ error: 'Invalid token' });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(403).json({ error: 'Token expired' });
    }
    console.error('Authentication error:', error);
    return res.status(500).json({ error: 'Authentication failed' });
  }
};

// Optional authentication (doesn't fail if no token)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      const usersCollection = getCollection('users');
      const user = await usersCollection.findOne(
        { _id: toObjectId(decoded.id) },
        { projection: { email: 1, full_name: 1, role: 1 } }
      );

      if (user) {
        req.user = {
          id: user._id.toString(),
          email: user.email,
          full_name: user.full_name,
          role: user.role
        };
      }
    }
    
    next();
  } catch (error) {
    // Don't fail for optional auth, just proceed without user
    next();
  }
};

// Require specific roles
export const requireRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: allowedRoles,
        current: req.user.role
      });
    }

    next();
  };
};

// Check if user is admin
export const requireAdmin = requireRole(['admin']);

// Check if user is doctor or admin
export const requireDoctor = requireRole(['admin', 'doctor']);
