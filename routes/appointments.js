import express from 'express';
import { getCollection, toObjectId, generateObjectId } from '../config/database.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { generateReferenceNumber } from '../utils/helpers.js';
import dayjs from 'dayjs';

const router = express.Router();

// Create new appointment (public endpoint)
router.post('/', async (req, res) => {
  try {
    const { date, appointment_date, appointment_time, hospital } = req.body;
    
    // Use date or appointment_date (frontend might send either)
    const dateToCheck = date || appointment_date;
    
    // Check if the appointment is for Friday
    const appointmentDateObj = dayjs(dateToCheck);
    if (appointmentDateObj.day() === 5) {
      return res.status(400).json({ error: 'Both hospitals are closed on Fridays' });
    }
    
    // Generate reference number
    const referenceNumber = generateReferenceNumber();
    
    // Create the appointment document
    const appointmentDoc = {
      _id: generateObjectId(),
      reference_number: referenceNumber,
      user_id: req.user ? toObjectId(req.user.id) : null,
      ...req.body,
      appointment_date: new Date(dateToCheck),
      created_at: new Date(),
      updated_at: new Date(),
      status: 'pending'
    };
    
    // Insert appointment
    const appointmentsCollection = getCollection('appointments');
    const result = await appointmentsCollection.insertOne(appointmentDoc);
    
    // Get the created appointment
    const appointment = await appointmentsCollection.findOne({ _id: result.insertedId });
    
    res.status(201).json({
      message: 'Appointment booked successfully',
      appointment: {
        ...appointment,
        id: appointment._id.toString()
      }
    });
  } catch (error) {
    console.error('Appointment creation error:', error);
    res.status(500).json({ error: 'Failed to book appointment' });
  }
});

// Track appointment by reference number (public endpoint)
router.get('/track/:refNumber', async (req, res) => {
  try {
    const { refNumber } = req.params;
    
    // Find appointment by reference number
    const appointmentsCollection = getCollection('appointments');
    const appointment = await appointmentsCollection.findOne({ reference_number: refNumber });
    
    if (!appointment) {
      return res.status(404).json({ error: 'Appointment not found with this reference number' });
    }
    
    // Return limited information for privacy
    const appointmentInfo = {
      reference_number: appointment.reference_number,
      patient_name: appointment.patient_name,
      appointment_date: appointment.appointment_date,
      appointment_time: appointment.appointment_time,
      hospital: appointment.hospital,
      status: appointment.status || 'pending',
      doctor_name: appointment.doctor_name,
      visit_completed: appointment.visit_completed || false,
      visit_summary: appointment.visit_summary,
      follow_up_required: appointment.follow_up_required || false,
      created_at: appointment.created_at,
      updated_at: appointment.updated_at
    };
    
    // Check for prescription
    if (appointment.prescription_id) {
      const prescriptionsCollection = getCollection('prescriptions');
      const prescription = await prescriptionsCollection.findOne({ _id: appointment.prescription_id });
      if (prescription) {
        appointmentInfo.has_prescription = true;
        appointmentInfo.prescription_reference = prescription.reference_number;
      } else {
        appointmentInfo.has_prescription = false;
      }
    } else {
      appointmentInfo.has_prescription = false;
    }
    
    res.json({ appointment: appointmentInfo });
  } catch (error) {
    console.error('Track appointment error:', error);
    res.status(500).json({ error: 'Failed to track appointment' });
  }
});

// Get all appointments for doctor portal (admin/doctor only)
router.get('/all', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { date, hospital, status, limit = 100, skip = 0 } = req.query;
    
    // Build query filter
    const filter = {};
    
    if (date) {
      const startDate = new Date(date);
      const endDate = new Date(date);
      endDate.setDate(endDate.getDate() + 1);
      filter.appointment_date = {
        $gte: startDate,
        $lt: endDate
      };
    }
    
    if (hospital) {
      filter.hospital = hospital;
    }
    
    if (status && status !== 'all') {
      filter.status = status;
    }
    
    // Get appointments from database
    const appointmentsCollection = getCollection('appointments');
    const appointments = await appointmentsCollection
      .find(filter)
      .sort({ appointment_date: -1, time: 1 })
      .limit(parseInt(limit))
      .skip(parseInt(skip))
      .toArray();
    
    // Transform data for frontend
    const formattedAppointments = appointments.map(appointment => ({
      id: appointment._id.toString(),
      reference_number: appointment.reference_number,
      name: appointment.patientName,
      email: appointment.patientEmail,
      phoneNumber: appointment.patientPhone,
      age: appointment.patientAge,
      gender: appointment.patientGender,
      address: appointment.patientAddress,
      problemDescription: appointment.problemDescription,
      hospital: {
        id: appointment.hospital,
        name: appointment.hospital
      },
      date: appointment.date,
      time: appointment.time,
      appointment_date: appointment.appointment_date,
      status: appointment.status || 'pending',
      doctorNotes: appointment.doctor_notes,
      created_at: appointment.created_at,
      updated_at: appointment.updated_at
    }));
    
    res.json({ 
      appointments: formattedAppointments,
      total: appointments.length 
    });
  } catch (error) {
    console.error('Fetch appointments error:', error);
    res.status(500).json({ error: 'Failed to fetch appointments' });
  }
});

// Update appointment status and notes (admin/doctor only)
router.put('/:id', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status, doctor_notes } = req.body;
    
    // Validate appointment ID
    if (!id) {
      return res.status(400).json({ error: 'Appointment ID is required' });
    }
    
    const updateData = {
      updated_at: new Date()
    };
    
    if (status) {
      updateData.status = status;
    }
    
    if (doctor_notes !== undefined) {
      updateData.doctor_notes = doctor_notes;
    }
    
    // Update appointment
    const appointmentsCollection = getCollection('appointments');
    const result = await appointmentsCollection.updateOne(
      { _id: toObjectId(id) },
      { $set: updateData }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Appointment not found' });
    }
    
    // Get updated appointment
    const updatedAppointment = await appointmentsCollection.findOne({ _id: toObjectId(id) });
    
    res.json({
      message: 'Appointment updated successfully',
      appointment: {
        ...updatedAppointment,
        id: updatedAppointment._id.toString()
      }
    });
  } catch (error) {
    console.error('Update appointment error:', error);
    res.status(500).json({ error: 'Failed to update appointment' });
  }
});

// Get appointment statistics (admin/doctor only)
router.get('/stats/overview', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const appointmentsCollection = getCollection('appointments');
    const today = new Date().toISOString().slice(0, 10);
    
    const totalAppointments = await appointmentsCollection.countDocuments();
    const pendingAppointments = await appointmentsCollection.countDocuments({ status: 'pending' });
    const confirmedAppointments = await appointmentsCollection.countDocuments({ status: 'confirmed' });
    const completedAppointments = await appointmentsCollection.countDocuments({ status: 'completed' });
    const cancelledAppointments = await appointmentsCollection.countDocuments({ status: 'cancelled' });
    const todayAppointments = await appointmentsCollection.countDocuments({ 
      appointment_date: { 
        $gte: new Date(today), 
        $lt: new Date(new Date(today).getTime() + 24 * 60 * 60 * 1000) 
      } 
    });
    const upcomingAppointments = await appointmentsCollection.countDocuments({ 
      appointment_date: { $gt: new Date(today) } 
    });

    res.json({
      stats: {
        total_appointments: totalAppointments,
        pending_appointments: pendingAppointments,
        confirmed_appointments: confirmedAppointments,
        completed_appointments: completedAppointments,
        cancelled_appointments: cancelledAppointments,
        today_appointments: todayAppointments,
        upcoming_appointments: upcomingAppointments
      }
    });
  } catch (error) {
    console.error('Fetch stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

export default router;
