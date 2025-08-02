import express from 'express';
import Slot from '../models/Slot.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import dayjs from 'dayjs';

const router = express.Router();

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

// Get available slots for a specific date and hospital
router.get('/:hospitalId/:date', async (req, res) => {
  try {
    const { hospitalId, date } = req.params;
    
    // Validate date format
    const requestedDate = dayjs(date);
    if (!requestedDate.isValid() || requestedDate.isBefore(dayjs(), 'day')) {
      return res.status(400).json({ error: 'Invalid date or date is in the past' });
    }
    
    // Check if it's Friday (day 5)
    const dayOfWeek = requestedDate.day();
    if (dayOfWeek === 5) {
      return res.json({ 
        message: 'Both hospitals are closed on Fridays',
        slots: []
      });
    }
    
    // Find hospital configuration
    const hospital = hospitals.find(h => h.id === hospitalId);
    if (!hospital) {
      return res.status(404).json({ error: 'Hospital not found' });
    }
    
    // Check if hospital operates on this day
    if (!hospital.visitDays.includes(dayOfWeek)) {
      return res.json({ 
        slots: [],
        message: 'Hospital is closed on this day'
      });
    }
    
    // Initialize slots for this date if they don't exist
    await initializeSlotsForDate(hospital, date);
    
    // Get available slots from database
    const slots = await Slot.find({
      hospital_id: hospitalId,
      date: date,
      is_available: true
    }).sort({ start_time: 1 });
    
    // Also get unavailable slots to show full schedule
    const unavailableSlots = await Slot.find({
      hospital_id: hospitalId,
      date: date,
      is_available: false
    }).sort({ start_time: 1 });
    
    const allSlots = await Slot.find({
      hospital_id: hospitalId,
      date: date
    }).sort({ start_time: 1 });
    
    res.json({ 
      slots: allSlots.map(slot => ({
        time_slot: slot.time_slot,
        start_time: slot.start_time,
        end_time: slot.end_time,
        available: slot.is_available,
        current_appointments: slot.current_appointments,
        max_appointments: slot.max_appointments,
        remaining_slots: slot.max_appointments - slot.current_appointments
      }))
    });
  } catch (error) {
    console.error('Fetch slots error:', error);
    res.status(500).json({ error: 'Failed to fetch slots' });
  }
});

// Get slot availability for multiple dates (for calendar view)
router.get('/:hospitalId/availability/:startDate/:endDate', async (req, res) => {
  try {
    const { hospitalId, startDate, endDate } = req.params;
    
    const hospital = hospitals.find(h => h.id === hospitalId);
    if (!hospital) {
      return res.status(404).json({ error: 'Hospital not found' });
    }
    
    const start = dayjs(startDate);
    const end = dayjs(endDate);
    const availability = {};
    
    let current = start;
    while (current.isBefore(end) || current.isSame(end)) {
      const dateStr = current.format('YYYY-MM-DD');
      const dayOfWeek = current.day();
      
      // Skip Fridays and days hospital doesn't operate
      if (dayOfWeek === 5 || !hospital.visitDays.includes(dayOfWeek)) {
        availability[dateStr] = { available_slots: 0, total_slots: 0, closed: true };
      } else {
        // Initialize slots if needed
        await initializeSlotsForDate(hospital, dateStr);
        
        const totalSlots = await Slot.countDocuments({
          hospital_id: hospitalId,
          date: dateStr
        });
        
        const availableSlots = await Slot.countDocuments({
          hospital_id: hospitalId,
          date: dateStr,
          is_available: true
        });
        
        availability[dateStr] = {
          available_slots: availableSlots,
          total_slots: totalSlots,
          closed: false
        };
      }
      
      current = current.add(1, 'day');
    }
    
    res.json({ availability });
  } catch (error) {
    console.error('Fetch availability error:', error);
    res.status(500).json({ error: 'Failed to fetch availability' });
  }
});

// Reset slot capacity (admin only)
router.patch('/:hospitalId/:date/:slotTime/reset', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { hospitalId, date, slotTime } = req.params;
    
    const slot = await Slot.findOne({
      hospital_id: hospitalId,
      date: date,
      start_time: slotTime
    });
    
    if (!slot) {
      return res.status(404).json({ error: 'Slot not found' });
    }
    
    slot.current_appointments = 0;
    slot.appointment_ids = [];
    slot.is_available = true;
    
    await slot.save();
    
    res.json({ 
      message: 'Slot reset successfully',
      slot: {
        time_slot: slot.time_slot,
        available: slot.is_available,
        current_appointments: slot.current_appointments,
        max_appointments: slot.max_appointments
      }
    });
  } catch (error) {
    console.error('Reset slot error:', error);
    res.status(500).json({ error: 'Failed to reset slot' });
  }
});

// Helper function to initialize slots for a date if they don't exist
async function initializeSlotsForDate(hospital, date) {
  const existingSlots = await Slot.countDocuments({
    hospital_id: hospital.id,
    date: date
  });
  
  if (existingSlots === 0) {
    const slotsToCreate = hospital.timeSlots.map(slot => ({
      hospital_id: hospital.id,
      hospital_name: hospital.name,
      date: date,
      time_slot: slot.display,
      start_time: slot.start,
      end_time: slot.end,
      max_appointments: 20,
      current_appointments: 0,
      is_available: true,
      appointment_ids: []
    }));
    
    await Slot.insertMany(slotsToCreate);
  }
}

// Bulk reset all slots to available (admin only)
router.patch('/bulk/reset-all', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const updatedSlots = await Slot.updateMany(
      {}, // Match all slots
      {
        $set: {
          is_available: true,
          current_appointments: 0,
          appointment_ids: []
        }
      }
    );
    
    res.json({ 
      message: 'All slots reset to available',
      updated_count: updatedSlots.modifiedCount
    });
  } catch (error) {
    console.error('Bulk reset error:', error);
    res.status(500).json({ error: 'Failed to reset slots' });
  }
});

// Initialize slots for date range (admin only)
router.post('/bulk/initialize', authenticateToken, requireRole(['admin']), async (req, res) => {
  try {
    const { startDate, endDate } = req.body;
    
    if (!startDate || !endDate) {
      return res.status(400).json({ error: 'startDate and endDate are required' });
    }
    
    const start = dayjs(startDate);
    const end = dayjs(endDate);
    let totalSlotsCreated = 0;
    
    for (const hospital of hospitals) {
      let current = start;
      while (current.isBefore(end) || current.isSame(end, 'day')) {
        const dateStr = current.format('YYYY-MM-DD');
        const dayOfWeek = current.day();
        
        // Skip Fridays and days hospital doesn't operate
        if (dayOfWeek !== 5 && hospital.visitDays.includes(dayOfWeek)) {
          await initializeSlotsForDate(hospital, dateStr);
          totalSlotsCreated += hospital.timeSlots.length;
        }
        
        current = current.add(1, 'day');
      }
    }
    
    res.json({ 
      message: 'Slots initialized for date range',
      date_range: `${startDate} to ${endDate}`,
      slots_created: totalSlotsCreated
    });
  } catch (error) {
    console.error('Bulk initialize error:', error);
    res.status(500).json({ error: 'Failed to initialize slots' });
  }
});

export default router;
