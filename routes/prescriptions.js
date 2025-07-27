import express from 'express';
import mongoose from 'mongoose';
import Prescription from '../models/Prescription.js';
import Appointment from '../models/Appointment.js';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { generatePrescriptionReferenceNumber } from '../utils/helpers.js';
import dayjs from 'dayjs';

const router = express.Router();

// Create new prescription (doctor/admin only)
router.post('/', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const {
      appointment_id,
      patient_name,
      patient_email,
      patient_age,
      diagnosis,
      medications,
      hospital,
      notes,
      valid_until,
      next_visit
    } = req.body;
    
    // Validate appointment exists
    const appointment = await Appointment.findById(appointment_id).session(session);
    if (!appointment) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Appointment not found' });
    }
    
    // Generate prescription reference number
    const prescriptionRefNumber = generatePrescriptionReferenceNumber();
    
    // Create prescription
    const prescription = new Prescription({
      reference_number: prescriptionRefNumber,
      appointment_id,
      patient_name,
      patient_email,
      patient_age,
      diagnosis,
      medications,
      doctor_name: req.user.full_name || 'Dr. Unknown',
      doctor_id: req.user.id,
      hospital,
      valid_until,
      notes,
      next_visit
    });
    
    await prescription.save({ session });
    
    // Update appointment with prescription reference
    await Appointment.findByIdAndUpdate(
      appointment_id,
      { 
        prescription_id: prescription._id,
        visit_completed: true,
        status: 'completed'
      },
      { session }
    );
    
    await session.commitTransaction();
    
    res.status(201).json({
      message: 'Prescription created successfully',
      prescription
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('Prescription creation error:', error);
    res.status(500).json({ error: 'Failed to create prescription' });
  } finally {
    session.endSession();
  }
});

// Get prescription by reference number (public endpoint)
router.get('/track/:refNumber', async (req, res) => {
  try {
    const { refNumber } = req.params;
    
    const prescription = await Prescription.findOne({ reference_number: refNumber })
      .populate('appointment_id', 'reference_number appointment_date appointment_time hospital')
      .exec();
    
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found with this reference number' });
    }
    
    // Return prescription information (sensitive data filtered for public access)
    const prescriptionInfo = {
      reference_number: prescription.reference_number,
      patient_name: prescription.patient_name,
      diagnosis: prescription.diagnosis,
      medications: prescription.medications,
      doctor_name: prescription.doctor_name,
      hospital: prescription.hospital,
      issued_date: prescription.issued_date,
      valid_until: prescription.valid_until,
      status: prescription.status,
      next_visit: prescription.next_visit,
      appointment_reference: prescription.appointment_id?.reference_number
    };
    
    res.json({ prescription: prescriptionInfo });
  } catch (error) {
    console.error('Track prescription error:', error);
    res.status(500).json({ error: 'Failed to track prescription' });
  }
});

// Get all prescriptions for a patient by email (authenticated)
router.get('/patient/:email', authenticateToken, async (req, res) => {
  try {
    const { email } = req.params;
    
    // Users can only access their own prescriptions unless they're admin/doctor
    if (req.user.email !== email && !['admin', 'doctor'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const prescriptions = await Prescription.find({ patient_email: email })
      .populate('appointment_id', 'reference_number appointment_date appointment_time hospital')
      .sort({ issued_date: -1 });
    
    res.json({ prescriptions });
  } catch (error) {
    console.error('Fetch patient prescriptions error:', error);
    res.status(500).json({ error: 'Failed to fetch prescriptions' });
  }
});

// Get all prescriptions (admin/doctor only)
router.get('/', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { page = 1, limit = 20, status, hospital, patient_email } = req.query;
    const skip = (page - 1) * limit;
    const filters = {};
    
    if (status) filters.status = status;
    if (hospital) filters.hospital = new RegExp(hospital, 'i');
    if (patient_email) filters.patient_email = new RegExp(patient_email, 'i');
    
    const prescriptions = await Prescription.find(filters)
      .populate('appointment_id', 'reference_number appointment_date appointment_time')
      .sort({ issued_date: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const totalPrescriptions = await Prescription.countDocuments(filters);
    
    res.json({
      prescriptions,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalPrescriptions / limit),
        totalCount: totalPrescriptions,
        hasNext: page * limit < totalPrescriptions,
        hasPrev: page > 1
      }
    });
  } catch (error) {
    console.error('Fetch prescriptions error:', error);
    res.status(500).json({ error: 'Failed to fetch prescriptions' });
  }
});

// Get single prescription (admin/doctor only)
router.get('/:id', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    
    const prescription = await Prescription.findById(id)
      .populate('appointment_id')
      .populate('doctor_id', 'full_name email')
      .exec();
    
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    res.json({ prescription });
  } catch (error) {
    console.error('Fetch prescription error:', error);
    res.status(500).json({ error: 'Failed to fetch prescription' });
  }
});

// Update prescription (doctor/admin only)
router.patch('/:id', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    // Remove fields that shouldn't be updated
    delete updates.reference_number;
    delete updates.appointment_id;
    delete updates.issued_date;
    
    const prescription = await Prescription.findByIdAndUpdate(
      id,
      updates,
      { new: true, runValidators: true }
    ).exec();
    
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    res.json({
      message: 'Prescription updated successfully',
      prescription
    });
  } catch (error) {
    console.error('Update prescription error:', error);
    res.status(500).json({ error: 'Failed to update prescription' });
  }
});

// Update prescription status (doctor/admin only)
router.patch('/:id/status', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    const validStatuses = ['active', 'completed', 'expired', 'cancelled'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }
    
    const prescription = await Prescription.findByIdAndUpdate(
      id,
      { status },
      { new: true, runValidators: true }
    ).exec();
    
    if (!prescription) {
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    res.json({
      message: 'Prescription status updated successfully',
      prescription
    });
  } catch (error) {
    console.error('Update prescription status error:', error);
    res.status(500).json({ error: 'Failed to update prescription status' });
  }
});

// Delete prescription (admin only)
router.delete('/:id', authenticateToken, requireRole(['admin']), async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { id } = req.params;
    
    const prescription = await Prescription.findById(id).session(session);
    if (!prescription) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Prescription not found' });
    }
    
    // Remove prescription reference from appointment
    await Appointment.findByIdAndUpdate(
      prescription.appointment_id,
      { $unset: { prescription_id: 1 } },
      { session }
    );
    
    // Delete prescription
    await Prescription.findByIdAndDelete(id).session(session);
    
    await session.commitTransaction();
    
    res.json({ message: 'Prescription deleted successfully' });
  } catch (error) {
    await session.abortTransaction();
    console.error('Delete prescription error:', error);
    res.status(500).json({ error: 'Failed to delete prescription' });
  } finally {
    session.endSession();
  }
});

// Get prescription statistics (admin/doctor only)
router.get('/stats/overview', authenticateToken, requireRole(['admin', 'doctor']), async (req, res) => {
  try {
    const totalPrescriptions = await Prescription.countDocuments();
    const activePrescriptions = await Prescription.countDocuments({ status: 'active' });
    const expiredPrescriptions = await Prescription.countDocuments({ status: 'expired' });
    const completedPrescriptions = await Prescription.countDocuments({ status: 'completed' });
    const cancelledPrescriptions = await Prescription.countDocuments({ status: 'cancelled' });
    
    // Count prescriptions by hospital
    const hospitalStats = await Prescription.aggregate([
      { $group: { _id: '$hospital', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    // Count recent prescriptions (last 30 days)
    const thirtyDaysAgo = dayjs().subtract(30, 'day').toDate();
    const recentPrescriptions = await Prescription.countDocuments({ 
      issued_date: { $gte: thirtyDaysAgo } 
    });
    
    res.json({
      stats: {
        total_prescriptions: totalPrescriptions,
        active_prescriptions: activePrescriptions,
        expired_prescriptions: expiredPrescriptions,
        completed_prescriptions: completedPrescriptions,
        cancelled_prescriptions: cancelledPrescriptions,
        recent_prescriptions: recentPrescriptions,
        by_hospital: hospitalStats
      }
    });
  } catch (error) {
    console.error('Fetch prescription stats error:', error);
    res.status(500).json({ error: 'Failed to fetch prescription statistics' });
  }
});

export default router;
