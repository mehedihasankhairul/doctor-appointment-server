import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { validateRegistration, validateLogin } from '../middleware/validation.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Register new user
router.post('/register', validateRegistration, async (req, res) => {
  try {
    const { email, password, full_name, phone, date_of_birth, gender, address } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }

    // Hash password
    const password_hash = await User.hashPassword(password);

    // Create user
    const user = new User({
      email,
      password_hash,
      full_name,
      phone,
      date_of_birth,
      gender,
      address
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === 11000) {
      return res.status(400).json({ error: 'User already exists with this email' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Doctor PIN configuration (in production, store this securely in the database)
const DOCTOR_PINS = {
  '123456': {
    id: 'demo-doctor-id',
    name: 'Dr. Ganesh',
    email: 'doctor@drganeshcs.com',
    role: 'doctor',
    specialization: 'Cardiology & Medicine'
  }
};

// Doctor login with PIN or email/password
router.post('/doctor-login', async (req, res) => {
  try {
    const { pin, email, password, loginType } = req.body;

    let user;
    
    if (loginType === 'pin') {
      // PIN-based authentication
      if (!pin || pin.length !== 6) {
        return res.status(400).json({ error: 'Invalid PIN format' });
      }
      
      const doctorData = DOCTOR_PINS[pin];
      if (!doctorData) {
        return res.status(401).json({ error: 'Invalid PIN' });
      }
      
      user = doctorData;
    } else {
      // Email/password authentication
      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
      }
      
      // Check if it's the doctor's email
      if (email === 'doctor@drganeshcs.com' && password === 'DrGanesh2024!') {
        user = {
          id: 'demo-doctor-id',
          name: 'Dr. Ganesh',
          email: 'doctor@drganeshcs.com',
          role: 'doctor',
          specialization: 'Cardiology & Medicine'
        };
      } else {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        name: user.name,
        loginType 
      },
      process.env.JWT_SECRET,
      { expiresIn: loginType === 'pin' ? '4h' : '24h' } // Shorter expiry for PIN access
    );

    res.json({
      message: 'Doctor login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        specialization: user.specialization,
        loginType
      }
    });
  } catch (error) {
    console.error('Doctor login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Login user
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email }).select('+password_hash');
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    user.last_login = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        email: user.email,
        full_name: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get user profile
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password_hash');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Update user profile
router.put('/profile', authenticateToken, async (req, res) => {
  try {
    const { full_name, phone, date_of_birth, gender, address } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { full_name, phone, date_of_birth, gender, address },
      { new: true, runValidators: true }
    ).select('-password_hash');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Profile updated successfully',
      user
    });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Change password
router.put('/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    // Get user with password hash
    const user = await User.findById(req.user.id).select('+password_hash');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    const isValidPassword = await user.comparePassword(currentPassword);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash new password and update
    user.password_hash = await User.hashPassword(newPassword);
    await user.save();

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

export default router;
