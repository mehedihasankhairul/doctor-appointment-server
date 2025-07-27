#!/usr/bin/env node

/**
 * Script to make all slots available for booking
 * This script will:
 * 1. Reset all existing slots to available status
 * 2. Clear current appointments count
 * 3. Ensure max_appointments is set to a reasonable number
 * 4. Initialize slots for future dates
 */

import dotenv from 'dotenv';
import { MongoClient } from 'mongodb';
import dayjs from 'dayjs';

// Load environment variables
dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'doctor-portal';

// Hospital configurations
const hospitals = [
  {
    id: "moon",
    name: "Moon Hospital", 
    visitDays: [0, 1, 2, 3, 4, 6], // Saturday to Thursday (0=Sunday, 6=Saturday)
    timeSlots: [
      { start: "15:00", end: "16:00", display: "03:00 PM - 04:00 PM" },
      { start: "16:00", end: "17:00", display: "04:00 PM - 05:00 PM" },
    ]
  },
  {
    id: "popular", 
    name: "Popular Diagnostic Centre",
    visitDays: [0, 1, 2, 3, 4, 6], // Saturday to Thursday (0=Sunday, 6=Saturday)
    timeSlots: [
      { start: "08:00", end: "09:00", display: "08:00 AM - 09:00 AM" },
      { start: "17:00", end: "18:00", display: "05:00 PM - 06:00 PM" },
      { start: "18:00", end: "19:00", display: "06:00 PM - 07:00 PM" },
      { start: "19:00", end: "20:00", display: "07:00 PM - 08:00 PM" },
    ]
  }
];

async function main() {
  console.log('🏥 Making All Slots Available for Booking');
  console.log('==========================================');

  if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI environment variable is not set');
    process.exit(1);
  }

  let client;
  
  try {
    // Connect to MongoDB
    console.log('📡 Connecting to MongoDB...');
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    
    const db = client.db(DB_NAME);
    const slotsCollection = db.collection('slots');
    
    console.log('✅ Connected to MongoDB');
    
    // 1. Reset all existing slots to available
    console.log('\n🔄 Resetting all existing slots to available...');
    
    const resetResult = await slotsCollection.updateMany(
      {}, // Match all documents
      {
        $set: {
          is_available: true,
          current_appointments: 0,
          max_appointments: 20,
          appointment_ids: []
        }
      }
    );
    
    console.log(`✅ Reset ${resetResult.modifiedCount} existing slots`);
    
    // 2. Initialize slots for the next 30 days
    console.log('\n📅 Initializing slots for the next 30 days...');
    
    const today = dayjs();
    const endDate = today.add(30, 'days');
    let totalSlotsCreated = 0;
    
    for (const hospital of hospitals) {
      console.log(`\n🏥 Processing ${hospital.name}...`);
      
      let currentDate = today;
      while (currentDate.isBefore(endDate) || currentDate.isSame(endDate, 'day')) {
        const dateStr = currentDate.format('YYYY-MM-DD');
        const dayOfWeek = currentDate.day();
        
        // Skip Fridays and days hospital doesn't operate
        if (dayOfWeek !== 5 && hospital.visitDays.includes(dayOfWeek)) {
          // Check if slots already exist for this date
          const existingSlots = await slotsCollection.countDocuments({
            hospital_id: hospital.id,
            date: dateStr
          });
          
          if (existingSlots === 0) {
            // Create slots for this date
            const slotsToCreate = hospital.timeSlots.map(slot => ({
              hospital_id: hospital.id,
              hospital_name: hospital.name,
              date: dateStr,
              time_slot: slot.display,
              start_time: slot.start,
              end_time: slot.end,
              max_appointments: 20,
              current_appointments: 0,
              is_available: true,
              appointment_ids: [],
              createdAt: new Date(),
              updatedAt: new Date()
            }));
            
            await slotsCollection.insertMany(slotsToCreate);
            totalSlotsCreated += slotsToCreate.length;
            
            console.log(`   ✅ Created ${slotsToCreate.length} slots for ${dateStr}`);
          } else {
            console.log(`   ⏭️  Slots already exist for ${dateStr} (${existingSlots} slots)`);
          }
        }
        
        currentDate = currentDate.add(1, 'day');
      }
    }
    
    console.log(`\n✅ Created ${totalSlotsCreated} new slots`);
    
    // 3. Get summary statistics
    console.log('\n📊 Slot Statistics:');
    
    for (const hospital of hospitals) {
      const totalSlots = await slotsCollection.countDocuments({
        hospital_id: hospital.id
      });
      
      const availableSlots = await slotsCollection.countDocuments({
        hospital_id: hospital.id,
        is_available: true
      });
      
      const bookedSlots = await slotsCollection.countDocuments({
        hospital_id: hospital.id,
        is_available: false
      });
      
      console.log(`\n🏥 ${hospital.name}:`);
      console.log(`   Total Slots: ${totalSlots}`);
      console.log(`   Available: ${availableSlots}`);
      console.log(`   Booked: ${bookedSlots}`);
      console.log(`   Availability: ${totalSlots > 0 ? Math.round((availableSlots / totalSlots) * 100) : 0}%`);
    }
    
    // 4. Show next few days availability
    console.log('\n📅 Next 7 Days Availability:');
    
    for (let i = 0; i < 7; i++) {
      const checkDate = today.add(i, 'days');
      const dateStr = checkDate.format('YYYY-MM-DD');
      const dayName = checkDate.format('dddd');
      
      let totalDaySlots = 0;
      let availableDaySlots = 0;
      
      for (const hospital of hospitals) {
        const hospitalSlots = await slotsCollection.countDocuments({
          hospital_id: hospital.id,
          date: dateStr
        });
        
        const hospitalAvailable = await slotsCollection.countDocuments({
          hospital_id: hospital.id,
          date: dateStr,
          is_available: true
        });
        
        totalDaySlots += hospitalSlots;
        availableDaySlots += hospitalAvailable;
      }
      
      const status = checkDate.day() === 5 ? '🚫 CLOSED (Friday)' : 
                    availableDaySlots === 0 ? '❌ No slots' :
                    availableDaySlots === totalDaySlots ? '✅ All available' :
                    `⚠️  ${availableDaySlots}/${totalDaySlots} available`;
      
      console.log(`   ${dateStr} (${dayName}): ${status}`);
    }
    
    console.log('\n🎉 All slots are now available for booking!');
    console.log('\n💡 Tips:');
    console.log('   • Slots are automatically created for the next 30 days');
    console.log('   • Each slot can accommodate up to 20 appointments');
    console.log('   • Hospitals are closed on Fridays');
    console.log('   • You can run this script again anytime to reset availability');
    
  } catch (error) {
    console.error('❌ Error making slots available:', error);
    process.exit(1);
  } finally {
    if (client) {
      await client.close();
      console.log('\n📡 Disconnected from MongoDB');
    }
  }
}

// Run the script
main().catch(console.error);
