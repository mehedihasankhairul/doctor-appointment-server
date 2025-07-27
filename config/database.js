import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

// MongoDB connection string
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://doctor-portal:doctor1234@cluster0.1eg3a.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Connection options for Mongoose
const options = {
  maxPoolSize: 20,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  retryWrites: true,
  w: 'majority'
};

// Connect to MongoDB using Mongoose
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI, options);
    console.log(`✅ Connected to MongoDB database: ${conn.connection.name}`);
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
};

// Get database instance (for native MongoDB operations if needed)
export const getDB = () => {
  return mongoose.connection.db;
};

// Get collection helper (for native MongoDB operations if needed)
export const getCollection = (collectionName) => {
  return mongoose.connection.db.collection(collectionName);
};

// Generate ObjectId
export const generateObjectId = () => new mongoose.Types.ObjectId();

// Convert string to ObjectId
export const toObjectId = (id) => {
  try {
    return new mongoose.Types.ObjectId(id);
  } catch (error) {
    throw new Error('Invalid ObjectId');
  }
};

// Handle application termination
process.on('SIGINT', async () => {
  await mongoose.connection.close();
  console.log('📡 MongoDB connection closed through app termination');
  process.exit(0);
});

export default connectDB;
