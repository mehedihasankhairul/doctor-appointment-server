import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';

// Import database connection
import connectDB from './config/database.js';

// Import routes
import appointmentRoutes from './routes/appointments.js';
import contentRoutes from './routes/content-mongo.js';
import contactRoutes from './routes/contact.js';
import reviewRoutes from './routes/reviews.js';
import authRoutes from './routes/auth.js';
import slotRoutes from './routes/slots.js';

// Load environment variables
dotenv.config();

// Connect to MongoDB
connectDB();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// CORS configuration for main domain and portal subdomain
const allowedOrigins = [
  process.env.CLIENT_URL || 'http://localhost:5173', // Local development
  process.env.MAIN_DOMAIN || 'https://drganeshcs.com', // Main domain from env
  'https://www.drganeshcs.com', // Main domain with www
  process.env.PORTAL_DOMAIN || 'https://portal.drganeshcs.com', // Portal subdomain from env
  'https://portal.drganeshcs.com', // Portal subdomain (hardcoded backup)
  'https://drganeshcs.com', // Main domain (hardcoded backup)
  'http://localhost:3000', // Alternative local port
  'http://localhost:5174', // Alternative local port
  'http://localhost:5173', // Vite default port
];

// If in development, allow all localhost origins
if (process.env.NODE_ENV === 'development') {
  allowedOrigins.push(/^http:\/\/localhost:\d+$/);
}

console.log('🔧 CORS Configuration:');
console.log('📋 Allowed Origins:', allowedOrigins);
console.log('🌍 Environment:', process.env.NODE_ENV);
console.log('🏥 Portal Domain:', process.env.PORTAL_DOMAIN);
console.log('🏠 Main Domain:', process.env.MAIN_DOMAIN);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);
    
    console.log(`🔍 CORS request from origin: ${origin}`);
    
    // Check if origin is in allowed list or matches regex patterns
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        return origin === allowedOrigin;
      } else if (allowedOrigin instanceof RegExp) {
        return allowedOrigin.test(origin);
      }
      return false;
    });
    
    if (isAllowed) {
      console.log(`✅ CORS allowed for origin: ${origin}`);
      callback(null, true);
    } else {
      console.warn(`❌ CORS blocked origin: ${origin}`);
      console.warn(`📋 Allowed origins:`, allowedOrigins);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  optionsSuccessStatus: 200 // For legacy browser support
}));

// Logging
app.use(morgan('combined'));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files (for uploads)
app.use('/uploads', express.static('uploads'));

// API Routes
app.use('/api/appointments', appointmentRoutes);
app.use('/api/content', contentRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/reviews', reviewRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/slots', slotRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime() 
  });
});

// CORS test endpoint
app.get('/api/cors-test', (req, res) => {
  res.json({ 
    message: 'CORS is working!',
    origin: req.headers.origin,
    userAgent: req.headers['user-agent'],
    timestamp: new Date().toISOString(),
    allowedOrigins: allowedOrigins
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Client URL: ${process.env.CLIENT_URL || 'http://localhost:5173'}`);
  console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
});
