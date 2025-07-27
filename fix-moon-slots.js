import mongoose from 'mongoose';
import Slot from './models/Slot.js';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cardiomed_clinic';

async function fixMoonSlots() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Delete all existing Moon Hospital slots (wrong schedule)
    const result = await Slot.deleteMany({ hospital_id: 'moon' });
    
    console.log(`✅ Deleted ${result.deletedCount} incorrect Moon Hospital slots`);
    console.log('🔄 Correct slots (3:00 PM - 5:00 PM) will be generated when first requested');
    console.log('');
    console.log('📅 CORRECT Moon Hospital Schedule:');
    console.log('   - 3:00 PM - 4:00 PM');
    console.log('   - 4:00 PM - 5:00 PM');
    console.log('   - Saturday to Thursday (closed Friday)');

    await mongoose.connection.close();
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

fixMoonSlots();
