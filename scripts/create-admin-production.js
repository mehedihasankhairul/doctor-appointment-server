import dotenv from 'dotenv';
import mongoose from 'mongoose';
import User from '../models/User.js';

// Load environment variables
dotenv.config();

// Production MongoDB connection string
const PRODUCTION_MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://doctor-portal:doctor1234@cluster0.1eg3a.mongodb.net/doctor-portal?retryWrites=true&w=majority&appName=Cluster0';

async function createAdminUserProduction() {
  try {
    // Connect to Production MongoDB
    console.log('🔗 Connecting to Production MongoDB...');
    console.log('📍 Database:', PRODUCTION_MONGODB_URI.replace(/\/\/[^:]+:[^@]+@/, '//***:***@')); // Hide credentials in log
    
    await mongoose.connect(PRODUCTION_MONGODB_URI);
    console.log('✅ Connected to Production MongoDB successfully');

    // Admin user credentials
    const adminData = {
      email: 'admin@drganeshcs.com',
      password: 'ganeshcs123',
      full_name: 'Dr. Ganesh Admin',
      role: 'admin',
      phone: '+91-9876543210',
      gender: 'male',
      is_active: true,
      email_verified: true
    };

    // Check if admin already exists
    console.log('🔍 Checking if admin user already exists in production...');
    const existingAdmin = await User.findOne({ email: adminData.email });
    
    if (existingAdmin) {
      console.log('⚠️  Admin user already exists with email:', adminData.email);
      console.log('👤 Existing admin details:');
      console.log('   - ID:', existingAdmin.id);
      console.log('   - Email:', existingAdmin.email);
      console.log('   - Name:', existingAdmin.full_name);
      console.log('   - Role:', existingAdmin.role);
      console.log('   - Created:', existingAdmin.createdAt);
      
      // Update the existing user
      console.log('\n🔄 Updating existing admin password and details...');
      existingAdmin.password_hash = await User.hashPassword(adminData.password);
      existingAdmin.full_name = adminData.full_name;
      existingAdmin.role = adminData.role;
      existingAdmin.phone = adminData.phone;
      existingAdmin.gender = adminData.gender;
      existingAdmin.is_active = true;
      existingAdmin.email_verified = true;
      
      await existingAdmin.save();
      console.log('✅ Admin user updated successfully in production!');
    } else {
      // Hash the password
      console.log('🔐 Hashing password...');
      const password_hash = await User.hashPassword(adminData.password);

      // Create the admin user
      console.log('👤 Creating admin user in production database...');
      const adminUser = new User({
        ...adminData,
        password_hash
      });

      await adminUser.save();
      console.log('✅ Admin user created successfully in production!');
    }

    // Display final admin details
    const admin = await User.findOne({ email: adminData.email });
    console.log('\n🎉 Production Admin User Details:');
    console.log('   - ID:', admin.id);
    console.log('   - Email:', admin.email);
    console.log('   - Name:', admin.full_name);
    console.log('   - Role:', admin.role);
    console.log('   - Phone:', admin.phone);
    console.log('   - Active:', admin.is_active);
    console.log('   - Email Verified:', admin.email_verified);
    console.log('   - Created:', admin.createdAt);
    console.log('   - Updated:', admin.updatedAt);
    
    console.log('\n🔑 Production Login Credentials:');
    console.log('   - Email: admin@drganeshcs.com');
    console.log('   - Password: ganeshcs123');
    
    console.log('\n🌐 You can now login at:');
    console.log('   - Production Portal: https://portal.drganeshcs.com');
    console.log('   - Main Website: https://drganeshcs.com (doctor portal)');
    
    console.log('\n🧪 Testing production API...');
    // We could test the API here, but we'll do it separately

  } catch (error) {
    console.error('❌ Error creating admin user in production:', error.message);
    if (error.code === 11000) {
      console.error('   - Duplicate key error: User with this email already exists');
    }
    if (error.name === 'MongoServerError') {
      console.error('   - MongoDB server error. Check connection and credentials.');
    }
    if (error.name === 'MongoNetworkError') {
      console.error('   - Network error. Check internet connection and MongoDB Atlas access.');
    }
  } finally {
    // Close connection
    await mongoose.connection.close();
    console.log('\n🔌 Production database connection closed');
    process.exit(0);
  }
}

// Run the script
console.log('🚀 Creating admin user in production environment...\n');
createAdminUserProduction();
