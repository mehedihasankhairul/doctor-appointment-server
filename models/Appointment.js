import mongoose from 'mongoose';

const appointmentSchema = new mongoose.Schema({
  reference_number: {
    type: String,
    unique: true,
    index: true
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: false // Can be null for guest appointments
  },
  patient_name: {
    type: String,
    required: true,
    trim: true
  },
  patient_email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  patient_phone: {
    type: String,
    required: true,
    trim: true
  },
  appointment_date: {
    type: Date,
    required: true
  },
  appointment_time: {
    type: String,
    required: true
  },
  hospital: {
    type: String,
    required: true,
    trim: true
  },
  patient_age: {
    type: Number,
    required: true,
    min: 0,
    max: 120
  },
  gender: {
    type: String,
    required: true,
    enum: ['male', 'female', 'other'],
    lowercase: true
  },
  symptoms: {
    type: String,
    trim: true
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'completed', 'cancelled', 'no-show'],
    default: 'pending'
  },
  notes: {
    type: String,
    trim: true
  },
  doctor_name: {
    type: String,
    trim: true
  },
  reminder_sent: {
    type: Boolean,
    default: false
  },
  follow_up_required: {
    type: Boolean,
    default: false
  },
  prescription_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Prescription',
    required: false
  },
  visit_completed: {
    type: Boolean,
    default: false
  },
  visit_summary: {
    type: String,
    trim: true
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      ret.id = ret._id;
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
});

// Indexes for performance
appointmentSchema.index({ reference_number: 1 });
appointmentSchema.index({ appointment_date: 1 });
appointmentSchema.index({ status: 1 });
appointmentSchema.index({ patient_email: 1 });
appointmentSchema.index({ user_id: 1 });
appointmentSchema.index({ hospital: 1 });

// Compound indexes
appointmentSchema.index({ appointment_date: 1, appointment_time: 1 });
appointmentSchema.index({ patient_email: 1, appointment_date: -1 });

const Appointment = mongoose.model('Appointment', appointmentSchema);

export default Appointment;
