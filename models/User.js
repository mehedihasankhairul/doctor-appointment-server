import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password_hash: {
    type: String,
    required: true
  },
  full_name: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  date_of_birth: {
    type: Date
  },
  gender: {
    type: String,
    enum: ['male', 'female', 'other'],
    lowercase: true
  },
  address: {
    type: String,
    trim: true
  },
  role: {
    type: String,
    enum: ['patient', 'doctor', 'admin'],
    default: 'patient'
  },
  is_active: {
    type: Boolean,
    default: true
  },
  email_verified: {
    type: Boolean,
    default: false
  },
  last_login: {
    type: Date
  },
  is_demo: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true, // Adds createdAt and updatedAt
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      delete ret.password_hash;
      return ret;
    }
  }
});

// Index for performance
// Note: email index is already created by unique: true in schema
userSchema.index({ role: 1 });

// Instance method to check password
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password_hash);
};

// Static method to hash password
userSchema.statics.hashPassword = async function(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password_hash')) return next();
  
  this.password_hash = await User.hashPassword(this.password_hash);
  next();
});

const User = mongoose.model('User', userSchema);

export default User;
